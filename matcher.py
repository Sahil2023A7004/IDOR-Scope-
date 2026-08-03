"""
matcher.py

Auto-matches requests between two users' captured traffic and finds
the one thing that's different between them - the resource ID that's
a candidate for swapping.

Basically a simplified version of the URL-matching trick from the VSF
paper (Section 6.3.II), scaled down for small datasets instead of
tens of thousands of requests.
"""

from dataclasses import dataclass


@dataclass
class MatchedPair:
    request_a: dict
    request_b: dict
    method: str
    path_template: str
    diff_index: int          # which path segment differs (-1 if none)
    id_value_a: str          # user A's own identifier value
    id_value_b: str          # user B's own identifier value
    diff_location: str = "path"  # "path" or "query"
    diff_key: str = ""           # query param name, if diff_location == "query"


def split_path(path):
    return [segment for segment in path.split("/") if segment != ""]


def path_similarity(path_a, path_b):
    """
    Count how many segments match at the same position.
    Returns -1 if the two paths have a different number of segments
    (too different to compare fairly).
    """
    segments_a, segments_b = split_path(path_a), split_path(path_b)
    if len(segments_a) != len(segments_b):
        return -1
    return sum(1 for x, y in zip(segments_a, segments_b) if x == y)


def find_path_diff(path_a, path_b):
    """
    Find the single path segment where two same-length paths differ.
    Returns None if they differ in more than one spot (too ambiguous
    to safely swap) or don't differ at all.
    """
    segments_a, segments_b = split_path(path_a), split_path(path_b)
    diffs = [i for i, (x, y) in enumerate(zip(segments_a, segments_b)) if x != y]
    if len(diffs) != 1:
        return None
    return diffs[0]


def find_query_diff(query_a, query_b):
    """
    Find the single query param where two requests differ in value.
    Returns None if the key sets don't match, or more/less than one
    value differs.
    """
    if set(query_a.keys()) != set(query_b.keys()):
        return None
    diffs = [key for key in query_a if query_a[key] != query_b.get(key)]
    if len(diffs) != 1:
        return None
    return diffs[0]


def find_matches(requests_a, requests_b, min_similarity_ratio=0.6):
    """
    For every successful request user A made, find the best-matching
    successful request user B made: same method, same path length,
    high segment-match ratio, and exactly one differing value.

    Returns a list of MatchedPair objects - these are the swap
    candidates ready for probing.
    """
    matched_pairs = []
    candidates_b = [r for r in requests_b if 200 <= r["status"] < 300]

    for request_a in requests_a:
        if not (200 <= request_a["status"] < 300):
            continue

        best_match = None
        best_score = -1

        for request_b in candidates_b:
            if request_a["method"] != request_b["method"]:
                continue

            score = path_similarity(request_a["path"], request_b["path"])
            if score == -1:
                continue

            segment_count = len(split_path(request_a["path"])) or 1
            ratio = score / segment_count

            if ratio >= min_similarity_ratio and score > best_score:
                best_match = request_b
                best_score = score

        if best_match is None:
            continue

        # try a path-based diff first
        diff_index = find_path_diff(request_a["path"], best_match["path"])
        if diff_index is not None:
            segments_a = split_path(request_a["path"])
            segments_b = split_path(best_match["path"])
            matched_pairs.append(MatchedPair(
                request_a=request_a, request_b=best_match, method=request_a["method"],
                path_template=request_a["path"], diff_index=diff_index,
                id_value_a=segments_a[diff_index], id_value_b=segments_b[diff_index],
                diff_location="path",
            ))
            continue

        # otherwise try a query-param diff
        diff_key = find_query_diff(request_a["query"], best_match["query"])
        if diff_key is not None:
            matched_pairs.append(MatchedPair(
                request_a=request_a, request_b=best_match, method=request_a["method"],
                path_template=request_a["path"], diff_index=-1,
                id_value_a=request_a["query"][diff_key],
                id_value_b=best_match["query"][diff_key],
                diff_location="query", diff_key=diff_key,
            ))

    return matched_pairs
