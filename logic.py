import json
import traceback
from datetime import datetime
from pathlib import Path

from flask import abort, jsonify, redirect, render_template, request, send_file, send_from_directory
from flask.views import View
from flask_login import login_required

# pylint: disable=import-error
from plugin import PluginModuleBase

# third-party
from werkzeug.exceptions import NotFound
from werkzeug.security import check_password_hash, generate_password_hash

# local
from .logic_auth import HTTPBasicAuth
from .setup import F, P

# from .plugin import plugin
plugin = P
logger = plugin.logger
package_name = plugin.package_name
ModelSetting = plugin.ModelSetting


class LogicMain(PluginModuleBase):
    db_default = {
        "rules": json.dumps(
            {
                f"/{package_name}/example": {
                    "location_path": f"/{package_name}/example",
                    "www_root": str(Path(__file__).resolve().parent.joinpath("example")),
                    "auth_type": "none",
                    "creation_date": datetime.now().isoformat(),
                }
            }
        ),
    }

    def __init__(self, P):
        super().__init__(P, None)

    def plugin_load(self):
        try:
            rules = json.loads(ModelSetting.get("rules"))
            LogicMain.register_rules(rules)
            ModelSetting.set("rules", json.dumps(rules))
        except Exception as e:
            logger.error("Exception:%s", e)
            logger.error(traceback.format_exc())

    def process_menu(self, sub, req):
        arg = ModelSetting.to_dict()
        if sub == "setting":
            arg["package_name"] = package_name
            arg["rule_size"] = len(json.loads(ModelSetting.get("rules")))
            return render_template(f"{package_name}_{sub}.html", sub=sub, arg=arg)
        return render_template("sample.html", title=f"{package_name} - {sub}")

    def process_ajax(self, sub, req):
        try:
            p = req.form.to_dict() if req.method == "POST" else req.args.to_dict()
            if sub == "add_rule":
                urlpath = p.get("urlpath-input", "").strip()
                LogicMain.check_urlpath(urlpath)

                target = p.get("target", "").strip()
                if not target.startswith(("https://", "http://")):
                    if not Path(target).exists():
                        raise ValueError("존재하지 않는 경로입니다.")

                new_rule = {
                    "location_path": urlpath,
                    "www_root": target,
                    "host": p.get("host", "").strip(),
                    "auth_type": p.get("auth-type"),
                    "creation_date": datetime.now().isoformat(),
                }

                if p.get("auth-type") == "basic":
                    username = p.get("username", "").strip()
                    password = p.get("password", "").strip()
                    if not (username and password):
                        raise ValueError("USER/PASS를 입력하세요.")
                    new_rule.update({"username": username, "password": generate_password_hash(password)})

                # 2022-10-31 by soju6jan
                # AssertionError: The setup method 'add_url_rule' can no longer be called on the application. It has already handled its first request, any changes will not be applied consistently. Make sure all imports, decorators, functions, etc. needed to set up the application are done before running it.
                # 구동 이후에 add_url_rule 에러 발생.
                # 최대한 체크한 후 재시작하라고 해야 할 것 같습니다.

                # 위와 같이 최근 flask 버전부터 app.run() 이후의 add_url_rule에 에러가 발생
                # 우선 db에 쓰고 재시작 후에 ui로 피드백

                drules = json.loads(ModelSetting.get("rules"))
                drules.update({urlpath: new_rule})
                ModelSetting.set("rules", json.dumps(drules))

                return jsonify({"success": True, "ret": new_rule})
            if sub == "rule":
                act = p.get("act", "")
                ret = p.get("ret", "list")
                urlpath = p.get("urlpath", "")
                drules = json.loads(ModelSetting.get("rules"))

                # apply action
                if act == "del" and urlpath in drules:
                    del drules[urlpath]

                if act:
                    ModelSetting.set("rules", json.dumps(drules))

                lrules = drules.values()
                if ret == "count":
                    return jsonify({"success": True, "ret": len(lrules)})
                if ret == "list":
                    lrules = sorted(lrules, key=lambda x: x["creation_date"], reverse=True)
                    counter = int(p.get("c", "0"))
                    pagesize = 20
                    if counter == 0:
                        lrules = lrules[:pagesize]
                    elif counter == len(lrules):
                        lrules = []
                    else:
                        lrules = lrules[counter : counter + pagesize]
                    return jsonify({"success": True, "ret": lrules, "nomore": len(lrules) != pagesize})
                raise NotImplementedError(f"Unknown return type: {ret}")
            if sub == "check_target":
                target = Path(p.get("target", ""))
                return jsonify(
                    {"success": True, "exists": target.exists(), "isfile": target.is_file(), "isdir": target.is_dir()}
                )
            raise NotImplementedError(f"Unknown sub type: {sub}")
        except Exception as e:
            logger.error("Exception:%s", e)
            logger.error(traceback.format_exc())
            return jsonify({"success": False, "log": str(e)})

    @staticmethod
    def register_rules(rules: dict):
        for urlpath, rule in rules.items():
            try:
                logger.debug("registering rule for urlpath '%s'", urlpath)
                LogicMain.register_rule(rule)
            except Exception:
                logger.exception("exception while registering rule for urlpath '%s' with %s:", urlpath, rule)
                rule["status"] = "error"
            else:
                rule["status"] = "success"

    @staticmethod
    def register_rule(v: dict) -> None:
        urlpath = v["location_path"].rstrip("/")
        target = v["www_root"]
        host = v.get("host", "")
        atype = v["auth_type"]
        view_name = str(urlpath.lstrip("/").replace("/", "-"))
        # view_name = str(lpath)
        if target.startswith(("https://", "http://")):
            view_func = RedirectView.as_view(view_name, target, host)
        elif Path(target).is_file():
            view_func = FileView.as_view(view_name, target, host)
        else:
            view_func = StaticView.as_view(view_name, target, host)
        if atype == "ff":
            view_func = login_required(view_func)
        elif atype == "basic":
            basicauth = LogicMain.get_basicauth({v["username"]: v["password"]})
            view_func = basicauth.login_required(view_func)
        if Path(target).is_dir():
            F.app.add_url_rule(urlpath + "/<path:path>", view_func=view_func)
            F.app.add_url_rule(urlpath + "/", view_func=view_func)
        else:
            F.app.add_url_rule(urlpath, view_func=view_func)

    @staticmethod
    def check_urlpath(urlpath: str):
        if not urlpath.startswith("/"):
            raise ValueError("URL Path는 /로 시작해야 합니다.")

        dangerous_path = ["/"]
        urlpath = urlpath.rstrip("/") + "/"
        rules = [str(r) for r in F.app.url_map.iter_rules() if str(r) not in dangerous_path]
        # for rr in sorted(rules):
        #     logger.debug(rr)
        reserved_path = [r.split("<")[0].rstrip("/") + "/" for r in rules if "<" in r]
        if any(urlpath.startswith(r) for r in reserved_path):
            raise ValueError("예약된 URL Path입니다.")
        exact_rules = [r.rstrip("/") + "/" for r in rules if "<" not in r]
        if any(urlpath == r for r in exact_rules):
            raise ValueError("이미 등록된 URL Path입니다.")

    @staticmethod
    def get_basicauth(users: dict):
        basicauth = HTTPBasicAuth()

        @basicauth.verify_password
        def verify_password(username, password):
            if username in users and check_password_hash(users.get(username), password):
                return username
            return False

        return basicauth


class StaticView(View):
    methods = ["GET"]

    def __init__(self, dirpath: str, host: str):
        self.dirpath = Path(dirpath)
        self.host = host

    def dispatch_request(self, path="index.html"):
        if self.host and self.host != request.host:
            return abort(404)
        try:
            if path == "favicon.ico":
                return send_from_directory(self.dirpath, path, mimetype="image/vnd.microsoft.icon")
            return send_from_directory(self.dirpath, path)
        except NotFound as e:
            current_root = self.dirpath.joinpath(path)
            if current_root.is_dir() and not path.endswith("/"):
                return redirect(path + "/", code=301)
            if path.endswith("/"):
                return send_from_directory(current_root, "index.html")
            raise e


class RedirectView(View):
    methods = ["GET"]

    def __init__(self, redirect_url: str, host: str):
        self.redirect_url = redirect_url
        self.host = host

    def dispatch_request(self):
        if self.host and self.host != request.host:
            return abort(404)
        return redirect(self.redirect_url)


class FileView(View):
    methods = ["GET"]

    def __init__(self, filepath: str, host: str):
        self.filepath = Path(filepath)
        self.host = host

    def dispatch_request(self):
        if self.host and self.host != request.host:
            return abort(404)
        return send_file(self.filepath, as_attachment=True)
