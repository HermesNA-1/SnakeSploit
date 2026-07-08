#!/usr/bin/env python3
"""
Nova Comprehensive Test Suite — finds every bug.
Tests every feature path, every command, every edge case.
"""

import sys
import os
import traceback

sys.path.insert(0, os.path.expanduser("~/snakesploit"))

PASS = 0
FAIL = 0
ERRORS = []


def test(name, fn):
    global PASS, FAIL
    try:
        fn()
        PASS += 1
        print(f"  ✅ {name}")
    except Exception as e:
        FAIL += 1
        tb = traceback.format_exc()
        ERRORS.append((name, str(e), tb))
        print(f"  ❌ {name}: {e}")


def assert_eq(a, b, msg=""):
    if a != b:
        raise AssertionError(f"{msg}: expected {b!r}, got {a!r}")


# ═══════════════════════════════════════════
#  1. CORE MODULE SYSTEM
# ═══════════════════════════════════════════

def test_module_manager_init():
    from core.module import ModuleManager
    mm = ModuleManager()
    assert mm.modules == {}, "modules should be empty dict"
    assert mm._loaded == False


def test_module_discovery():
    from core.module import ModuleManager
    mm = ModuleManager()
    total = mm.discover()
    assert total >= 2, f"Should find at least 2 modules, found {total}"
    assert 'aux' in mm.categories, "Should have 'aux' category"


def test_module_loading():
    from core.module import ModuleManager
    mm = ModuleManager()
    mm.discover()
    for cat, paths in mm.categories.items():
        for p in paths:
            inst = mm.load_module(p)
            if inst:
                assert inst.metadata is not None, "Module must have metadata"
                assert inst.metadata.name, "Module must have name"
    assert len(mm.modules) >= 2, f"Should load at least 2 modules, got {len(mm.modules)}"


def test_module_search():
    from core.module import ModuleManager
    mm = ModuleManager()
    mm.discover()
    for cat, paths in mm.categories.items():
        for p in paths:
            mm.load_module(p)
    results = mm.search("smb")
    assert len(results) >= 1, "Search 'smb' should find SMB module"
    results = mm.search("http")
    assert len(results) >= 1, "Search 'http' should find HTTP module"
    results = mm.search("NONEXISTENT_XYZ_999")
    assert len(results) == 0, "Bad search should return empty"


def test_module_get_nonexistent():
    from core.module import ModuleManager
    mm = ModuleManager()
    assert mm.get_module("does_not_exist") is None
    assert mm.get_module("") is None


def test_module_reload_all():
    from core.module import ModuleManager
    mm = ModuleManager()
    mm.discover()
    for cat, paths in mm.categories.items():
        for p in paths:
            mm.load_module(p)
    initial = len(mm.modules)
    count = mm.reload_all()
    assert count >= initial, f"Reload should return at least {initial} modules, got {count}"


def test_nova_module_base():
    from core.module import NovaModule
    # Can't instantiate NovaModule directly (no metadata), but we can test methods
    # Test that subclasses work
    from modules.aux.http_banner_grabber import Module as HTTPModule
    mod = HTTPModule()
    assert mod.metadata.name == "http_banner_grabber"
    assert "RHOSTS" in mod.required_options
    assert "RPORT" in mod.required_options

    # Test setup() chaining
    mod.setup(RHOSTS="127.0.0.1", RPORT=80)
    assert mod.options["RHOSTS"] == "127.0.0.1"
    assert mod.options["RPORT"] == 80

    # Test validate()
    mod.validate()  # Should not raise

    # Test validate with missing options
    mod2 = HTTPModule()
    try:
        mod2.validate()
        raise AssertionError("Should have raised RuntimeError for missing options")
    except RuntimeError:
        pass  # Expected


# ═══════════════════════════════════════════
#  2. TARGET MANAGEMENT
# ═══════════════════════════════════════════

def test_target_manager_init():
    from core.target import TargetManager
    tm = TargetManager()
    assert len(tm.targets) == 0


def test_target_add():
    from core.target import TargetManager
    tm = TargetManager()
    t = tm.add("192.168.1.1")
    assert t.host == "192.168.1.1"
    # Adding same host returns existing
    t2 = tm.add("192.168.1.1")
    assert t2 is t


def test_target_get():
    from core.target import TargetManager
    tm = TargetManager()
    tm.add("10.0.0.1")
    t = tm.get("10.0.0.1")
    assert t is not None
    assert tm.get("1.2.3.4") is None


def test_target_remove():
    from core.target import TargetManager
    tm = TargetManager()
    tm.add("10.0.0.1")
    tm.remove("10.0.0.1")
    assert tm.get("10.0.0.1") is None


def test_target_all():
    from core.target import TargetManager
    tm = TargetManager()
    assert len(tm.all()) == 0
    tm.add("10.0.0.1")
    tm.add("10.0.0.2")
    assert len(tm.all()) == 2


def test_target_vulnerabilities():
    from core.target import Target, Service, TargetManager
    t = Target(host="10.0.0.1")
    t.add_vulnerability("CVE-2020-0796", "SMBGhost", source="test")
    assert len(t.vulnerabilities) == 1
    assert t.vulnerabilities[0]["cve_id"] == "CVE-2020-0796"

    # Test adding service
    svc = Service(port=445, service="smb")
    t.add_service(svc)
    assert len(t.services) == 1
    assert t.services[445].service == "smb"


def test_target_search():
    from core.target import TargetManager
    tm = TargetManager()
    tm.add("10.0.0.1")
    results = tm.search("10.0.")
    assert len(results) >= 1
    results = tm.search("NONEXISTENT")
    assert len(results) == 0


def test_target_save_load():
    import tempfile, json
    from core.target import TargetManager
    # Override db path
    tm = TargetManager()
    tm._db_path = "/tmp/test_nova_targets.json"
    # Clean state
    if os.path.exists(tm._db_path):
        os.remove(tm._db_path)
    tm.add("10.0.0.1")
    tm.save()
    assert os.path.exists(tm._db_path)
    # Load into fresh manager
    tm2 = TargetManager()
    tm2._db_path = "/tmp/test_nova_targets.json"
    tm2.load()
    assert tm2.get("10.0.0.1") is not None
    os.remove(tm._db_path)


# ═══════════════════════════════════════════
#  3. SESSION MANAGEMENT
# ═══════════════════════════════════════════

def test_session_manager_init():
    from core.session import SessionManager
    sm = SessionManager()
    assert len(sm.sessions) == 0


def test_session_create():
    from core.session import SessionManager
    sm = SessionManager()
    s = sm.create_session("reverse", "10.0.0.1", 4444)
    assert s.id.startswith("rev_")
    assert s.target_host == "10.0.0.1"
    assert s.target_port == 4444
    assert not s.dead


def test_session_get():
    from core.session import SessionManager
    sm = SessionManager()
    s = sm.create_session("reverse", "10.0.0.1", 4444)
    assert sm.get(s.id) is s
    assert sm.get("nonexistent") is None


def test_session_close():
    from core.session import SessionManager
    sm = SessionManager()
    s = sm.create_session("reverse", "10.0.0.1", 4444)
    sm.close_session(s.id)
    assert s.dead


def test_session_list():
    from core.session import SessionManager
    sm = SessionManager()
    s1 = sm.create_session("reverse", "10.0.0.1", 4444)
    s2 = sm.create_session("bind", "10.0.0.2", 5555)
    s2.dead = True
    assert len(sm.list_active()) == 1
    assert len(sm.list_dead()) == 1
    assert len(sm.sessions) == 2

    summary = sm.summary()
    assert summary["total"] == 2
    assert summary["active"] == 1
    assert summary["dead"] == 1


# ═══════════════════════════════════════════
#  4. NETWORK LIBRARY
# ═══════════════════════════════════════════

def test_port_scanner_scan():
    from lib.network import PortScanner
    # Scan localhost — should find at least SSH or something
    results = PortScanner.scan("127.0.0.1", [22, 80, 443])
    assert isinstance(results, list)


def test_http_get():
    from lib.network import HTTPClient
    result = HTTPClient.get("http://httpbin.org/get", timeout=5)
    if "error" not in result:
        assert "status" in result
    # If it fails due to no network, that's OK — just check it doesn't crash


def test_port_scanner_single():
    from lib.network import PortScanner
    state = PortScanner.scan_port("127.0.0.1", 22, timeout=1)
    assert state in ("open", "closed", "filtered")


def test_nova_socket():
    from lib.network import NovaSocket
    # Just test init, not actual connection (may fail on network-less env)
    assert NovaSocket is not None


# ═══════════════════════════════════════════
#  5. PAYLOAD SYSTEM
# ═══════════════════════════════════════════

def test_payload_generation():
    from lib.payloads import PayloadGenerator
    for name in ["linux_reverse", "python_reverse", "nc_reverse"]:
        p = PayloadGenerator.generate(name, "10.0.0.5", 4444)
        assert p.name == name
        assert p.lhost == "10.0.0.5"
        assert p.lport == 4444
        assert p.code != ""
        assert p.size > 0


def test_payload_encode():
    from lib.payloads import PayloadGenerator
    p = PayloadGenerator.generate("python_reverse", "10.0.0.5", 4444, encode=True)
    assert p.encoded
    assert p.encoder == "base64"
    assert p.code != ""


def test_payload_bind():
    from lib.payloads import PayloadGenerator
    p = PayloadGenerator.generate("python_bind", lport=5555)
    assert p.payload_type == "bind_shell"
    assert "5555" in p.code or "5555" in str(p.code)


def test_payload_unknown():
    from lib.payloads import PayloadGenerator
    try:
        PayloadGenerator.generate("nonexistent_payload", "1.2.3.4", 4444)
        raise AssertionError("Should have raised ValueError")
    except ValueError:
        pass  # Expected


def test_powershell_payload():
    from lib.payloads import PayloadGenerator
    p = PayloadGenerator.generate("powershell_reverse", "10.0.0.5", 4444)
    assert "TCPClient" in p.code
    assert "10.0.0.5" in p.code


# ═══════════════════════════════════════════
#  6. CVE UPDATER
# ═══════════════════════════════════════════

def test_cve_updater_init():
    from updater.cve_fetcher import CVEUpdater
    updater = CVEUpdater()
    assert updater.cache_dir is not None
    assert updater.index is not None


def test_cve_statistics():
    from updater.cve_fetcher import CVEUpdater
    updater = CVEUpdater()
    stats = updater.get_statistics()
    assert "total_cves" in stats
    assert "critical" in stats
    assert "high" in stats
    assert "medium" in stats


def test_cve_severity_filter():
    from updater.cve_fetcher import CVEUpdater
    updater = CVEUpdater()
    critical = updater.get_cves_by_severity("CRITICAL")
    assert isinstance(critical, list)
    for c in critical:
        assert c.get("severity") == "CRITICAL", f"Expected CRITICAL, got {c.get('severity')}"


def test_cves_without_pocs():
    from updater.cve_fetcher import CVEUpdater
    updater = CVEUpdater()
    no_pocs = updater.get_cves_without_pocs()
    assert isinstance(no_pocs, list)
    for c in no_pocs:
        assert not c.get("has_poc"), f"CVE {c['id']} should not have PoC"


# ═══════════════════════════════════════════
#  7. POINTS OF FAILURE & EDGE CASES
# ═══════════════════════════════════════════

def test_console_init():
    from console import SnakeSploitConsole
    c = SnakeSploitConsole()
    assert c.module_manager is not None
    assert c.target_manager is not None
    assert c.session_manager is not None
    assert c.cve_updater is not None
    assert c.poc_scraper is not None
    assert c.module_generator is not None
    assert c.auto_updater is not None


def test_empty_help():
    from console import SnakeSploitConsole
    c = SnakeSploitConsole()
    # These should not crash
    c.onecmd("help")
    c.onecmd("help search")
    c.onecmd("help update")
    c.onecmd("help use")


def test_empty_commands():
    from console import SnakeSploitConsole
    c = SnakeSploitConsole()
    # Empty commands should not crash
    c.onecmd("")
    c.emptyline()
    c.default("foo bar baz")


def test_banner():
    from console import SnakeSploitConsole
    c = SnakeSploitConsole()
    c.onecmd("banner")  # Should not crash


def test_clear():
    from console import SnakeSploitConsole
    c = SnakeSploitConsole()
    c.onecmd("clear")  # Should not crash


def test_shell_command():
    from console import SnakeSploitConsole
    c = SnakeSploitConsole()
    c.onecmd("shell echo 'nova test'")  # Should not crash


def test_commands_without_active_module():
    """These should show helpful errors, not crash."""
    from console import SnakeSploitConsole
    c = SnakeSploitConsole()
    c.onecmd("show options")      # No active module
    c.onecmd("show info")         # No active module
    c.onecmd("set RHOSTS x")      # No active module
    c.onecmd("check")             # No active module
    c.onecmd("run")               # No active module
    c.onecmd("back")              # No active module


def test_list_categories():
    from console import SnakeSploitConsole
    c = SnakeSploitConsole()
    c.onecmd("list")              # All modules
    c.onecmd("list aux")          # Aux category


def test_use_module_workflow():
    """Test full module lifecycle."""
    from console import SnakeSploitConsole
    c = SnakeSploitConsole()

    # use a module
    c.onecmd("use http_banner_grabber")
    assert c._active_module is not None
    assert c._active_module_name == "auxiliary/http_banner_grabber"

    # show info
    c.onecmd("show info")
    assert c._active_module is not None

    # show options (none set yet)
    c.onecmd("show options")

    # set options
    c.onecmd("set RHOSTS 127.0.0.1")
    assert c._active_module.options.get("RHOSTS") == "127.0.0.1"
    c.onecmd("set RPORT 8080")
    assert c._active_module.options.get("RPORT") == "8080"
    c.onecmd("set TARGETURI /")
    assert c._active_module.options.get("TARGETURI") == "/"

    # check (should not crash, might just fail to connect)
    c.onecmd("check")

    # back
    c.onecmd("back")
    assert c._active_module is None


def test_reload_modules():
    from console import SnakeSploitConsole
    c = SnakeSploitConsole()
    c.onecmd("reload modules")  # Should not crash


def test_target_commands():
    from console import SnakeSploitConsole
    c = SnakeSploitConsole()

    c.onecmd("targets")                  # List (empty initially)
    c.onecmd("targets add 10.0.0.1")    # Add
    assert c.target_manager.get("10.0.0.1") is not None
    c.onecmd("targets show 10.0.0.1")   # Show
    c.onecmd("targets rm 10.0.0.1")     # Remove
    assert c.target_manager.get("10.0.0.1") is None


def test_cve_commands():
    from console import SnakeSploitConsole
    c = SnakeSploitConsole()
    c.onecmd("cve stats")  # Should not crash


def test_payload_commands():
    from console import SnakeSploitConsole
    c = SnakeSploitConsole()

    # List payloads
    c.onecmd("payloads")

    # Generate a payload
    c.onecmd("payloads python_reverse LHOST=10.0.0.5 LPORT=4444")


def test_listener_commands():
    from console import SnakeSploitConsole
    c = SnakeSploitConsole()
    # List listeners (should be empty)
    c.onecmd("listener")


def test_sessions_commands():
    from console import SnakeSploitConsole
    c = SnakeSploitConsole()
    # List sessions (should be empty)
    c.onecmd("sessions")

    # Kill nonexistent session
    c.onecmd("sessions -k nonexistent")


def test_scan():
    from console import SnakeSploitConsole
    c = SnakeSploitConsole()
    c.onecmd("scan 127.0.0.1 22,80,443")  # Should not crash


def test_http_command():
    from console import SnakeSploitConsole
    c = SnakeSploitConsole()
    c.onecmd("http http://127.0.0.1")  # Should not crash (just fail gracefully)


# ═══════════════════════════════════════════
#  8. AUTO-GENERATED MODULE FILES
# ═══════════════════════════════════════════

def test_generated_modules_syntax():
    """Check all generated modules for basic Python syntax validity."""
    import py_compile
    gen_dir = os.path.expanduser("~/snakesploit/data/modules_generated")
    if not os.path.isdir(gen_dir):
        return  # No generated modules yet, skip

    failed = []
    for f in os.listdir(gen_dir):
        if f.endswith(".py"):
            path = os.path.join(gen_dir, f)
            try:
                py_compile.compile(path, doraise=True)
            except py_compile.PyCompileError as e:
                failed.append((f, str(e)))

    if failed:
        msg = "\n".join(f"  {f}: {e}" for f, e in failed[:5])
        raise AssertionError(f"{len(failed)} generated modules have syntax errors:\n{msg}")


# ═══════════════════════════════════════════
#  RUN ALL TESTS
# ═══════════════════════════════════════════

if __name__ == "__main__":
    # Clear target/session DBs to start clean
    for f in ["~/.nova/targets.json", "~/.nova/sessions.json"]:
        p = os.path.expanduser(f)
        if os.path.exists(p):
            os.remove(p)

    print(f"\n{'═'*60}")
    print(f"  SNAKESPLOIT COMPREHENSIVE TEST SUITE")
    print(f"{'═'*60}\n")

    tests = [
        # Core module system
        ("ModuleManager init", test_module_manager_init),
        ("Module discovery", test_module_discovery),
        ("Module loading", test_module_loading),
        ("Module search", test_module_search),
        ("Module get nonexistent", test_module_get_nonexistent),
        ("Module reload all", test_module_reload_all),
        ("NovaModule base class", test_nova_module_base),

        # Target management
        ("TargetManager init", test_target_manager_init),
        ("Target add", test_target_add),
        ("Target get", test_target_get),
        ("Target remove", test_target_remove),
        ("Target all", test_target_all),
        ("Target vulnerabilities", test_target_vulnerabilities),
        ("Target search", test_target_search),
        ("Target save/load", test_target_save_load),

        # Session management
        ("SessionManager init", test_session_manager_init),
        ("Session create", test_session_create),
        ("Session get", test_session_get),
        ("Session close", test_session_close),
        ("Session list", test_session_list),

        # Network library
        ("Port scanner scan", test_port_scanner_scan),
        ("HTTP GET request", test_http_get),
        ("Port scanner single", test_port_scanner_single),
        ("NovaSocket init", test_nova_socket),

        # Payload system
        ("Payload generation", test_payload_generation),
        ("Payload encoding", test_payload_encode),
        ("Bind payload", test_payload_bind),
        ("Unknown payload error", test_payload_unknown),
        ("PowerShell payload", test_powershell_payload),

        # CVE updater
        ("CVEUpdater init", test_cve_updater_init),
        ("CVE statistics", test_cve_statistics),
        ("CVE severity filter", test_cve_severity_filter),
        ("CVEs without PoCs", test_cves_without_pocs),

        # Console
        ("Console init", test_console_init),
        ("Empty help", test_empty_help),
        ("Empty commands", test_empty_commands),
        ("Banner", test_banner),
        ("Clear", test_clear),
        ("Shell command", test_shell_command),
        ("Commands without module", test_commands_without_active_module),
        ("List categories", test_list_categories),
        ("Use module workflow", test_use_module_workflow),
        ("Reload modules", test_reload_modules),
        ("Target commands", test_target_commands),
        ("CVE commands", test_cve_commands),
        ("Payload commands", test_payload_commands),
        ("Listener commands", test_listener_commands),
        ("Session commands", test_sessions_commands),
        ("Scan command", test_scan),
        ("HTTP command", test_http_command),
    ]

    for name, fn in tests:
        test(name, fn)

    # Generated modules syntax check (separate because it can be heavy)
    try:
        test_generated_modules_syntax()
        PASS += 1
        print(f"  ✅ Generated module syntax check")
    except AssertionError as e:
        FAIL += 1
        ERRORS.append(("Generated module syntax", str(e), ""))

    print(f"\n{'═'*60}")
    print(f"  RESULTS: {PASS} passed, {FAIL} failed")
    print(f"{'═'*60}")

    if ERRORS:
        print(f"\n{'─'*60}")
        print(f"  FAILURE DETAILS:")
        print(f"{'─'*60}")
        for name, err, tb in ERRORS:
            print(f"\n  ❌ {name}")
            print(f"     {err}")
            if "assert" in err.lower() or "Traceback" in tb:
                for line in tb.split("\n")[-4:]:
                    if line.strip():
                        print(f"     {line.strip()}")

    exit(0 if FAIL == 0 else 1)