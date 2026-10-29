import json

white_list = ["api", "graphql", "v1", "v2", "v3", "user", "profile", "account", "settings", "me", "dashboard", "wallet",
              "update", "edit", "delete", "create", "upload", "download", "payment",
               "id=", "uid=", "user_id="]

def load(path):
    with open(path, "r", encoding="utf-8") as f:
        clean_list = []
        data = json.load(f)
        print("Total requests in file:", len(data["log"]["entries"]))
        for d in data["log"]["entries"]:
            url = d["request"]["url"]
            if any(clean in url for clean in white_list):
                clean_list.append(d)
        print(clean_list,"\n")
        return clean_list
name = input("enter path to file or file name: ")
saved_file = load(name)
