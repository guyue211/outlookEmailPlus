from __future__ import annotations

import argparse
from typing import Sequence

from outlook_web.services.temp_mail_plugin_manager import (
    PluginManagerError,
    check_provider_in_use,
    get_installed_plugins,
    install_plugin,
    uninstall_plugin,
)
from outlook_web.services.temp_mail_provider_factory import get_available_providers


def _confirm(prompt: str) -> bool:
    answer = input(f"{prompt} [y/N]: ").strip().lower()
    return answer in {"y", "yes"}


def _cmd_install(name: str, url: str | None) -> int:
    if url:
        print(f"[警告] 该插件来自自定义地址，未经过官方审核: {url}")
    if not _confirm(f"确认安装插件 {name} 吗？"):
        print("已取消")
        return 1

    try:
        # 命令行是显式的本地操作，允许走自定义来源；仍会经过地址校验与源码审计。
        result = install_plugin(name, url=url, allow_custom=bool(url))
    except PluginManagerError as exc:
        print(f"[错误] {exc.code}: {exc.message}")
        return 1

    print(f"[OK] 插件 {result['plugin_name']} 已安装")
    print(f"文件路径: {result['file_path']}")

    dependencies = result.get("dependencies") or []
    if dependencies:
        print("检测到额外依赖，请手动安装：")
        for item in dependencies:
            print(f"- {item}")
    return 0


def _cmd_uninstall(name: str) -> int:
    usage = check_provider_in_use(name)
    task_count = int(usage.get("task_count", 0) or 0)
    active_count = int(usage.get("active_count", 0) or 0)
    if task_count > 0:
        print(f"[错误] 当前有 {task_count} 个进行中的任务邮箱，不能卸载 {name}")
        return 1
    if active_count > 0:
        print(f"[提示] 当前有 {active_count} 个活跃邮箱记录，卸载后仅保留历史记录")

    if not _confirm(f"确认卸载插件 {name} 吗？"):
        print("已取消")
        return 1

    try:
        result = uninstall_plugin(name)
    except PluginManagerError as exc:
        print(f"[错误] {exc.code}: {exc.message}")
        return 1

    print(f"[OK] 插件 {result['plugin_name']} 已卸载")
    return 0


def _cmd_list() -> int:
    installed_names = {str(item.get("name") or "") for item in get_installed_plugins()}
    providers = get_available_providers()
    if not providers:
        print("没有已注册的 Provider。")
        return 0

    for item in providers:
        name = str(item.get("name") or "")
        label = str(item.get("label") or name)
        version = str(item.get("version") or "")
        provider_type = "插件" if name in installed_names else "内置"
        suffix = f" ({version})" if version else ""
        print(f"[{provider_type}] {name} - {label}{suffix}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python web_outlook_app.py")
    sub = parser.add_subparsers(dest="command")

    install_parser = sub.add_parser("install-provider", help="安装临时邮箱 Provider 插件")
    install_parser.add_argument("name")
    install_parser.add_argument("--from", dest="url", default=None)

    uninstall_parser = sub.add_parser("uninstall-provider", help="卸载临时邮箱 Provider 插件")
    uninstall_parser.add_argument("name")

    sub.add_parser("list-providers", help="查看已注册 Provider")

    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.command == "install-provider":
        return _cmd_install(args.name, args.url)
    if args.command == "uninstall-provider":
        return _cmd_uninstall(args.name)
    if args.command == "list-providers":
        return _cmd_list()

    parser.print_help()
    return 0
