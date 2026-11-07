import sys
import gzip
import ipaddress
import io
import html
import json
import re
from pathlib import Path
from urllib.error import URLError
from urllib.parse import parse_qs, quote, urlencode, urlsplit
from urllib.request import Request, urlopen

from PyQt6 import sip
from PyQt6.QtCore import QSettings, QStandardPaths, QThread, QTimer, Qt, QUrl, pyqtSignal
from PyQt6.QtGui import QCursor, QKeySequence, QShortcut
from PyQt6.QtWebEngineCore import (
    QWebEngineDownloadRequest,
    QWebEnginePage,
    QWebEngineProfile,
    QWebEngineSettings,
    QWebEngineUrlRequestInterceptor,
)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QPlainTextEdit,
    QProgressBar,
    QComboBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTabWidget,
    QToolBar,
    QVBoxLayout,
    QWidget,
)


class PrivacyRequestInterceptor(QWebEngineUrlRequestInterceptor):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.tracking_protection_enabled = True
        self.threat_protection_enabled = True
        self.threat_domains = frozenset()
        self.threat_urls = frozenset()
        self.tracker_domains = frozenset()

    def interceptRequest(self, info):
        request_url = info.requestUrl()
        host = request_url.host().lower()
        tracker_blocked = self.tracking_protection_enabled and (
            domain_is_blocked(host, self.tracker_domains)
            or any(
                host == domain or host.endswith("." + domain)
                for domain in ("google-analytics.com", "doubleclick.net")
            )
        )
        threat_blocked = self.threat_protection_enabled and url_is_blocked(
            request_url, self.threat_domains, self.threat_urls
        )
        if tracker_blocked or threat_blocked:
            info.block(True)


def domain_is_blocked(host, domains):
    host = host.lower().rstrip(".")
    labels = host.split(".")
    return any(".".join(labels[index:]) in domains for index in range(len(labels)))


def normalize_threat_url(value):
    try:
        parsed = urlsplit(value.strip())
        host = parsed.hostname
        if parsed.scheme.lower() not in ("http", "https") or not host:
            return None
        host = host.encode("idna").decode("ascii").lower().rstrip(".")
        port = parsed.port
    except (UnicodeError, ValueError):
        return None
    default_port = 80 if parsed.scheme.lower() == "http" else 443
    if port and port != default_port:
        host = f"{host}:{port}"
    path = parsed.path or "/"
    return f"{host}{path}?{parsed.query}" if parsed.query else f"{host}{path}"


def url_is_blocked(url, domains, threat_urls):
    host = url.host().lower()
    return domain_is_blocked(host, domains) or (
        normalize_threat_url(url.toString()) in threat_urls
    )


def normalize_home_url(value):
    text = str(value).strip()
    if not text or any(character.isspace() for character in text):
        return None
    if "://" not in text:
        text = "https://" + text
    url = QUrl.fromUserInput(text)
    if not url.isValid() or url.scheme() not in ("http", "https") or not url.host():
        return None
    return url.toString()


def parse_domain_feed(contents):
    domains = set()
    for raw_line in contents.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = re.split(r"[\s,;]+", line)
        parts = [part for part in parts if part]
        if parts[0].startswith(("http://", "https://")):
            parts = [parts[0]]
        elif len(parts) > 1:
            try:
                ipaddress.ip_address(parts[0])
                parts = parts[1:]
            except ValueError:
                pass
        for candidate in parts:
            if candidate.startswith(("http://", "https://")):
                candidate = urlsplit(candidate).hostname or ""
            candidate = candidate.lower().rstrip(".")
            if candidate.startswith("www."):
                candidate = candidate[4:]
            try:
                ipaddress.ip_address(candidate)
                continue
            except ValueError:
                pass
            if len(candidate) <= 253 and re.fullmatch(
                r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
                candidate,
            ) and len(candidate.rsplit(".", 1)[-1]) >= 2:
                domains.add(candidate)
    return domains


def parse_threat_feed_line(raw_line):
    line = raw_line.strip()
    if not line or line.startswith(("#", "!")):
        return set(), set()
    line = line.split("#", 1)[0].strip()
    if not line:
        return set(), set()

    urls = set()
    for match in re.findall(r"https?://[^\s\"'<>]+", line, flags=re.IGNORECASE):
        candidate = match.rstrip(",;)]}")
        normalized = normalize_threat_url(candidate)
        if normalized:
            urls.add(normalized)
    if not urls and not any(character.isspace() for character in line):
        candidate = line.strip(" ,;\"'")
        if candidate.startswith("//"):
            candidate = candidate[2:]
        if "/" in candidate and "://" not in candidate:
            normalized = normalize_threat_url("https://" + candidate)
            if normalized:
                urls.add(normalized)
    if urls:
        return set(), urls

    domains = set()
    parts = line.split()
    if len(parts) > 1:
        try:
            ipaddress.ip_address(parts[0])
            parts = parts[1:]
        except ValueError:
            pass
    for part in parts:
        candidate = part.strip(" ,;\"'")
        if candidate.startswith("*."):
            candidate = candidate[2:]
        candidate = candidate.lower().rstrip(".")
        try:
            ipaddress.ip_address(candidate)
            continue
        except ValueError:
            pass
        if len(candidate) <= 253 and re.fullmatch(
            r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
            candidate,
        ) and len(candidate.rsplit(".", 1)[-1]) >= 2:
            domains.add(candidate)
    return domains, urls


def parse_threat_feed(lines):
    domains = set()
    urls = set()
    for line in lines:
        line_domains, line_urls = parse_threat_feed_line(line)
        domains.update(line_domains)
        urls.update(line_urls)
    return {"domains": domains, "urls": urls}


def parse_saved_threat_urls(values):
    urls = set()
    for value in values:
        text = str(value).strip()
        if "://" not in text:
            text = "https://" + text
        normalized = normalize_threat_url(text)
        if normalized:
            urls.add(normalized)
    return urls


def is_local_host(host):
    host = host.lower().rstrip(".")
    if not host or "." not in host and ":" not in host:
        return True  # empty or single-label (intranet) names
    if host.endswith((".localhost", ".local", ".lan", ".internal")):
        return True
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return address.is_loopback or address.is_private or address.is_link_local


def parse_site_list(text):
    sites = set()
    for line in str(text).splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        if "://" in line:
            line = urlsplit(line).hostname or ""
        line = line.strip("/ .")
        if line:
            sites.add(line)
    return frozenset(sites)


def interstitial_html(title, heading, message, actions):
    buttons = "".join(
        f'<a class="{kind}" href="{html.escape(href, quote=True)}">{html.escape(label)}</a>'
        for label, href, kind in actions
    )
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>{html.escape(title)}</title>
<style>
body {{ margin:0; background:#16181d; color:#e6e9ef; font:16px/1.5 system-ui,sans-serif;
  display:flex; min-height:100vh; align-items:center; justify-content:center; }}
main {{ max-width:560px; padding:32px; }}
h1 {{ font-size:26px; margin:0 0 12px; }}
p {{ color:#b4bac6; word-break:break-word; }}
a {{ display:inline-block; margin:12px 10px 0 0; padding:9px 16px; border-radius:7px;
  text-decoration:none; font-size:14px; }}
a.primary {{ background:#3982e4; color:white; }}
a.danger {{ border:1px solid #6b7280; color:#b4bac6; }}
</style></head><body><main><h1>{html.escape(heading)}</h1>{message}{buttons}</main></body></html>"""


MAX_FEED_BYTES = 64 * 1024 * 1024  # cap on decompressed bytes read per feed


class FeedAborted(Exception):
    pass


class CappedReader(io.RawIOBase):
    """Raw reader that enforces a byte cap and honours a stop request."""

    def __init__(self, stream, limit, should_stop):
        super().__init__()
        self._stream = stream
        self._remaining = limit
        self._should_stop = should_stop

    def readable(self):
        return True

    def readinto(self, buffer):
        if self._should_stop():
            raise FeedAborted("update cancelled")
        data = self._stream.read(len(buffer))
        self._remaining -= len(data)
        if self._remaining < 0:
            raise ValueError(f"feed is larger than {MAX_FEED_BYTES // (1024 * 1024)} MB")
        buffer[: len(data)] = data
        return len(data)


class ThreatFeedUpdateThread(QThread):
    feeds_updated = pyqtSignal(object)
    update_failed = pyqtSignal(str)
    FEEDS = (
        "https://openphish.com/feed.txt",
        "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-links-ACTIVE.txt",
        "https://data.mendeley.com/datasets/vfszbj9b36/1/files/97e4b9fc-8c55-4579-ae80-d30740d00913",
        "https://data.mendeley.com/datasets/vfszbj9b36/1/files/f0de314f-ea72-4385-9faa-f06593bb0a2d",
        "https://ismalicious.com/downloads/blocklist/blocklist-domains-phishing.txt",
    )
    TRACKER_FEEDS = (
        "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
        "https://v.firebog.net/hosts/Easyprivacy.txt",
    )

    def run(self):
        threat_list = {"domains": set(), "urls": set(), "trackers": set(), "errors": []}
        for feed_url in self.FEEDS:
            if self.isInterruptionRequested():
                return
            try:
                request = Request(
                    feed_url,
                    headers={
                        "User-Agent": "FlameDarkness/1.0 threat-list updater",
                        "Accept-Encoding": "gzip",
                    },
                )
                with urlopen(request, timeout=15) as response:
                    stream = response
                    if response.headers.get("Content-Encoding", "").lower() == "gzip":
                        stream = gzip.GzipFile(fileobj=response)
                    capped = io.BufferedReader(
                        CappedReader(
                            stream, MAX_FEED_BYTES, self.isInterruptionRequested
                        )
                    )
                    text_stream = io.TextIOWrapper(
                        capped, encoding="utf-8", errors="replace"
                    )
                    parsed = parse_threat_feed(text_stream)
                if not parsed["domains"] and not parsed["urls"]:
                    raise ValueError(f"No entries were found in feed: {feed_url}")
                threat_list["domains"].update(parsed["domains"])
                threat_list["urls"].update(parsed["urls"])
            except FeedAborted:
                return
            except (URLError, TimeoutError, OSError, ValueError, EOFError) as error:
                threat_list["errors"].append(f"{feed_url}: {error}")
        for feed_url in self.TRACKER_FEEDS:
            if self.isInterruptionRequested():
                return
            try:
                request = Request(
                    feed_url,
                    headers={
                        "User-Agent": "FlameDarkness/1.0 tracker-list updater",
                        "Accept-Encoding": "gzip",
                    },
                )
                with urlopen(request, timeout=15) as response:
                    stream = response
                    if response.headers.get("Content-Encoding", "").lower() == "gzip":
                        stream = gzip.GzipFile(fileobj=response)
                    text_stream = io.TextIOWrapper(
                        io.BufferedReader(
                            CappedReader(
                                stream, MAX_FEED_BYTES, self.isInterruptionRequested
                            )
                        ),
                        encoding="utf-8",
                        errors="replace",
                    )
                    trackers = parse_domain_feed(text_stream.read())
                if not trackers:
                    raise ValueError(f"No entries were found in feed: {feed_url}")
                threat_list["trackers"].update(trackers)
            except FeedAborted:
                return
            except (URLError, TimeoutError, OSError, ValueError, EOFError) as error:
                threat_list["errors"].append(f"{feed_url}: {error}")
        if self.isInterruptionRequested():
            return
        if not (threat_list["domains"] or threat_list["urls"] or threat_list["trackers"]):
            self.update_failed.emit(
                "\n".join(threat_list["errors"]) or "No entries were found in the feeds."
            )
            return
        self.feeds_updated.emit(threat_list)


class BrowserPage(QWebEnginePage):
    threatBlocked = pyqtSignal(str)
    mainFrameThreat = pyqtSignal(QUrl)
    httpBlocked = pyqtSignal(QUrl)
    permissionDenied = pyqtSignal(str, str)
    ALLOW_HTTP_HOST = "allow-http.flame-darkness.invalid"

    def __init__(self, profile, parent, interceptor, site_exceptions):
        super().__init__(profile, parent)
        self.interceptor = interceptor
        self.site_exceptions = site_exceptions
        self.allowed_http_hosts = set()
        # Deny every site permission (camera, mic, location, notifications, ...).
        self.permissionRequested.connect(self._deny_permission)

    def _deny_permission(self, permission):
        permission.deny()
        try:
            kind = permission.permissionType().name
        except AttributeError:
            kind = "permission"
        self.permissionDenied.emit(permission.origin().host(), kind)

    def acceptNavigationRequest(self, url, navigation_type, is_main_frame):
        if is_main_frame and url.host().lower() == self.ALLOW_HTTP_HOST:
            # "Continue over HTTP" link; only honoured from our own warning page.
            if self.url().scheme() in ("data", "about"):
                values = parse_qs(url.query()).get("u", [])
                target = QUrl(values[0]) if values else QUrl()
                if target.scheme() == "http" and target.host():
                    self.allowed_http_hosts.add(target.host().lower())
                    QTimer.singleShot(0, lambda: self.setUrl(target))
            return False
        if (
            self.interceptor.threat_protection_enabled
            and url_is_blocked(
                url,
                self.interceptor.threat_domains,
                self.interceptor.threat_urls,
            )
        ):
            self.threatBlocked.emit(url.host())
            if is_main_frame:
                self.mainFrameThreat.emit(url)
            return False
        if is_main_frame and url.scheme() in ("http", "https"):
            host = url.host().lower()
            if (
                url.scheme() == "http"
                and not is_local_host(host)
                and host not in self.allowed_http_hosts
            ):
                self.httpBlocked.emit(url)
                return False
            # Canvas readback and clipboard access only on sites the user allowed.
            allowed = domain_is_blocked(host, self.site_exceptions())
            settings = self.settings()
            settings.setAttribute(
                QWebEngineSettings.WebAttribute.ReadingFromCanvasEnabled, allowed
            )
            settings.setAttribute(
                QWebEngineSettings.WebAttribute.JavascriptCanAccessClipboard, allowed
            )
        return super().acceptNavigationRequest(url, navigation_type, is_main_frame)


class FlameDarknessWindow(QMainWindow):
    HOME_URL = "https://www.google.com"

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Flame Darkness")
        self.resize(1200, 680)
        self.setMinimumSize(720, 480)
        self.preferences = QSettings("FlameDarkness", "FlameDarknessBrowser")
        saved_home_url = normalize_home_url(
            self.preferences.value("home_url", self.HOME_URL)
        )
        self.home_url = saved_home_url or self.HOME_URL
        if saved_home_url is None:
            self.preferences.setValue("home_url", self.home_url)
        self.javascript_enabled = self.preferences.value(
            "javascript_enabled", True, type=bool
        )
        self.dark_mode_enabled = self.preferences.value("dark_mode_enabled", True, type=bool)
        self.threat_protection_enabled = self.preferences.value(
            "threat_protection_enabled", True, type=bool
        )
        self.tracking_protection_enabled = self.preferences.value(
            "tracking_protection_enabled", True, type=bool
        )
        self.search_engine = self.preferences.value("search_engine", "Google")
        self.threat_list_path = Path(
            QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppDataLocation)
        ) / "threat_domains.json"
        self.threat_urls = set()
        self.tracker_domains = set()
        self.site_exceptions = parse_site_list(
            self.preferences.value("site_exceptions", "")
        )
        self.upgrade_attempts = {}
        self.interstitial_urls = {}
        self.threat_domains = self.load_threat_domains()
        self.feed_thread = None

        self.profile = QWebEngineProfile(self)
        # Keep Chromium's real user agent (so it matches the client hints it sends),
        # minus the QtWebEngine token that makes this browser stand out.
        self.profile.setHttpUserAgent(
            re.sub(r"\s*QtWebEngine/\S+", "", self.profile.httpUserAgent())
        )
        self.profile.setHttpCacheType(QWebEngineProfile.HttpCacheType.MemoryHttpCache)
        self.profile.setPersistentCookiesPolicy(
            QWebEngineProfile.PersistentCookiesPolicy.NoPersistentCookies
        )
        self.profile.cookieStore().setCookieFilter(
            lambda request: not request.thirdParty
        )
        self.interceptor = PrivacyRequestInterceptor(self)
        self.interceptor.threat_domains = frozenset(self.threat_domains)
        self.interceptor.threat_urls = frozenset(self.threat_urls)
        self.interceptor.tracker_domains = frozenset(self.tracker_domains)
        self.interceptor.threat_protection_enabled = self.threat_protection_enabled
        self.interceptor.tracking_protection_enabled = self.tracking_protection_enabled
        self.profile.setUrlRequestInterceptor(self.interceptor)
        self.profile.downloadRequested.connect(self.download_requested)

        self.bookmarks = []
        self.history = []
        self.downloads = []
        self.shortcuts = []
        self._build_ui()
        self._add_shortcuts()
        self.add_tab(self.home_url)

    def _build_ui(self):
        self.setStyleSheet("""
            QMainWindow { background: #f3f5f8; }
            QToolBar {
                background: #f3f5f8; border: 0; spacing: 5px;
                padding: 5px 10px;
            }
            QToolButton {
                color: #202630; background: transparent; border: 0;
                border-radius: 7px; padding: 7px 10px; font-size: 13px;
            }
            QToolButton:hover { background: #dfe5ed; }
            QToolButton:pressed { background: #cbd6e3; }
            QLineEdit {
                background: white; border: 1px solid #aeb8c5;
                border-radius: 10px; padding: 8px 13px; color: #202630;
            }
            QLineEdit:focus { border: 2px solid #3976c5; }
            QTabWidget::pane { border: 0; background: white; }
            QTabBar { background: #e3e7ed; }
            QTabBar::tab {
                background: #e3e7ed; color: #303946; padding: 9px 18px;
                margin: 4px 2px 0; border-top-left-radius: 7px;
                border-top-right-radius: 7px; min-width: 90px;
            }
            QTabBar::tab:selected { background: white; color: #161b22; }
            QTabBar::tab:hover:!selected { background: #d5dce5; }
            QStatusBar { background: #f3f5f8; color: #374151; }
            QGroupBox {
                color: #202630; font-size: 14px; font-weight: 600;
                border: 1px solid #cbd2dc; border-radius: 8px;
                margin-top: 12px; padding: 14px 12px 10px;
            }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }
            QLabel { color: #293241; }
            QCheckBox { color: #202630; spacing: 8px; padding: 4px 0; }
            QPushButton, QComboBox {
                color: #202630; background: #ffffff;
                border: 1px solid #aeb8c5; border-radius: 6px;
                padding: 7px 10px; min-height: 20px;
            }
            QPushButton:hover, QComboBox:hover { background: #edf2f8; }
            QPushButton:pressed { background: #dfe8f3; }
            QProgressBar { border: 0; background: transparent; height: 3px; }
            QProgressBar::chunk { background: #3982e4; }
        """)

        navigation_toolbar = self.navigation_toolbar = QToolBar("Navigation")
        navigation_toolbar.setMovable(False)
        navigation_toolbar.setFloatable(False)
        self.addToolBar(navigation_toolbar)
        navigation_toolbar.addAction("Back", self.active_view_back)
        navigation_toolbar.addAction("Forward", self.active_view_forward)
        navigation_toolbar.addAction("Reload", self.active_view_reload)
        navigation_toolbar.addAction("Home", self.go_home)
        navigation_toolbar.addAction("New Tab", lambda: self.add_tab(self.home_url))

        self.url_bar = QLineEdit()
        self.url_bar.setPlaceholderText("Search or enter website name")
        self.url_bar.setClearButtonEnabled(True)
        self.url_bar.setMinimumWidth(280)
        self.url_bar.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.url_bar.returnPressed.connect(self.navigate_to_url)
        navigation_toolbar.addWidget(self.url_bar)

        tools_toolbar = self.tools_toolbar = QToolBar("Browser tools")
        tools_toolbar.setMovable(False)
        tools_toolbar.setFloatable(False)
        self.addToolBar(tools_toolbar)
        self.bookmark_action = tools_toolbar.addAction("Bookmark", self.add_bookmark)
        self.bookmark_action.setToolTip("Bookmark this page")
        self.bookmarks_action = tools_toolbar.addAction("Bookmarks", self.show_bookmarks)
        self.bookmarks_action.setToolTip("Your bookmarks (this session only)")
        tools_toolbar.addAction("History", self.show_history)
        tools_toolbar.addAction("Downloads", self.show_downloads)
        tools_toolbar.addAction("Settings", self.open_settings)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(self.sync_active_tab)

        self.find_bar = QWidget()
        find_layout = QHBoxLayout(self.find_bar)
        find_layout.setContentsMargins(12, 8, 12, 8)
        find_layout.addWidget(QLabel("Find"))
        self.find_input = QLineEdit()
        self.find_input.setPlaceholderText("Find on page")
        self.find_input.textChanged.connect(self.find_in_page)
        self.find_input.returnPressed.connect(self.find_next)
        find_layout.addWidget(self.find_input)
        find_layout.addWidget(self._button("Previous", self.find_previous))
        find_layout.addWidget(self._button("Next", self.find_next))
        find_layout.addWidget(self._button("×", self.close_find))
        self.find_bar.hide()

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setTextVisible(False)
        self.progress.hide()

        center = QWidget()
        layout = QVBoxLayout(center)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.tabs)
        layout.addWidget(self.find_bar)
        layout.addWidget(self.progress)
        self.setCentralWidget(center)
        self.statusBar().showMessage("Private browsing · History and cookies are cleared when you close the browser")
        self._build_settings_page()

    def _build_settings_page(self):
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(44, 32, 44, 32)
        layout.setSpacing(16)
        heading = QLabel("Settings")
        heading.setStyleSheet("font-size: 26px; font-weight: 600; color: #202630;")
        layout.addWidget(heading)
        description = QLabel("Customize Flame Darkness. Preferences are saved on this device.")
        description.setStyleSheet("color: #657080;")
        layout.addWidget(description)

        general = QGroupBox("General")
        general_form = QFormLayout(general)
        self.homepage_input = QLineEdit(self.home_url)
        self.homepage_input.setPlaceholderText("https://google.com")
        general_form.addRow("Homepage", self.homepage_input)
        self.search_engine_combo = QComboBox()
        self.search_engine_combo.addItems(("Google", "DuckDuckGo", "Bing"))
        search_index = self.search_engine_combo.findText(self.search_engine)
        self.search_engine_combo.setCurrentIndex(max(search_index, 0))
        general_form.addRow("Search engine", self.search_engine_combo)
        layout.addWidget(general)

        appearance = QGroupBox("Appearance and websites")
        appearance_layout = QVBoxLayout(appearance)
        self.dark_mode_setting = QCheckBox("Use dark appearance for websites")
        self.dark_mode_setting.setChecked(self.dark_mode_enabled)
        self.dark_mode_setting.toggled.connect(self.set_dark_mode)
        appearance_layout.addWidget(self.dark_mode_setting)
        self.javascript_setting = QCheckBox("Allow JavaScript")
        self.javascript_setting.setChecked(self.javascript_enabled)
        self.javascript_setting.toggled.connect(self.set_javascript_enabled)
        appearance_layout.addWidget(self.javascript_setting)
        layout.addWidget(appearance)

        privacy = QGroupBox("Privacy")
        privacy_layout = QVBoxLayout(privacy)
        self.tracking_setting = QCheckBox("Block known tracking domains (needs list update)")
        self.tracking_setting.setChecked(self.tracking_protection_enabled)
        self.tracking_setting.toggled.connect(self.set_tracking_protection)
        privacy_layout.addWidget(self.tracking_setting)
        self.third_party_cookie_setting = QCheckBox("Block third-party cookies")
        self.third_party_cookie_setting.setChecked(True)
        self.third_party_cookie_setting.setEnabled(False)
        self.third_party_cookie_setting.setToolTip(
            "Third-party cookies are always blocked in this private browser."
        )
        privacy_layout.addWidget(self.third_party_cookie_setting)
        privacy_layout.addWidget(
            self._button("Clear session history", self.clear_history)
        )
        layout.addWidget(privacy)

        exceptions = QGroupBox("Site exceptions")
        exceptions_layout = QVBoxLayout(exceptions)
        exceptions_note = QLabel(
            "JavaScript clipboard access is off by default. List sites that need it "
            "(one per line, subdomains included), then press Save settings. The canvas "
            "readback switch is applied the same way, but Qt may not enforce it, so "
            "don't rely on it against fingerprinting."
        )
        exceptions_note.setWordWrap(True)
        exceptions_note.setStyleSheet("color: #657080;")
        exceptions_layout.addWidget(exceptions_note)
        self.site_exceptions_input = QPlainTextEdit(
            "\n".join(sorted(self.site_exceptions))
        )
        self.site_exceptions_input.setPlaceholderText("example.com")
        self.site_exceptions_input.setFixedHeight(90)
        exceptions_layout.addWidget(self.site_exceptions_input)
        layout.addWidget(exceptions)

        security = QGroupBox("Fraudulent website protection")
        security_layout = QVBoxLayout(security)
        self.threat_protection_setting = QCheckBox(
            "Block known phishing and malware domains"
        )
        self.threat_protection_setting.setChecked(self.threat_protection_enabled)
        self.threat_protection_setting.toggled.connect(
            self.set_threat_protection
        )
        security_layout.addWidget(self.threat_protection_setting)
        self.threat_list_status = QLabel()
        self.threat_list_status.setWordWrap(True)
        self.threat_list_status.setStyleSheet("color: #657080;")
        security_layout.addWidget(self.threat_list_status)
        self.update_feeds_button = QPushButton("Update threat lists")
        self.update_feeds_button.clicked.connect(self.update_threat_feeds)
        security_layout.addWidget(self.update_feeds_button, alignment=Qt.AlignmentFlag.AlignLeft)
        feed_note = QLabel(
            "Uses online phishing and malware feeds. Exact listed URLs and listed domains "
            "(including their subdomains) are blocked before navigation; URL feeds are also "
            "checked against page and resource requests. Lists are stored locally, and visited "
            "sites are not sent to feed providers. This is not a guarantee of safety."
        )
        feed_note.setWordWrap(True)
        feed_note.setStyleSheet("color: #657080;")
        security_layout.addWidget(feed_note)
        layout.addWidget(security)

        save_row = QHBoxLayout()
        save_row.addStretch(1)
        save_button = QPushButton("Save settings")
        save_button.clicked.connect(self.save_general_settings)
        save_row.addWidget(save_button)
        layout.addLayout(save_row)
        layout.addStretch(1)

        self.settings_page = QScrollArea()
        self.settings_page.setWidgetResizable(True)
        self.settings_page.setFrameShape(QScrollArea.Shape.NoFrame)
        self.settings_page.setWidget(content)
        self.refresh_threat_list_status()

    def load_threat_domains(self):
        try:
            data = json.loads(self.threat_list_path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return parse_domain_feed("\n".join(str(domain) for domain in data))
            if not isinstance(data, dict):
                raise ValueError("the stored threat list has an invalid format")
            domains = data.get("domains", [])
            urls = data.get("urls", [])
            if not isinstance(domains, list) or not isinstance(urls, list):
                raise ValueError("the stored threat list has invalid entries")
            self.threat_urls = parse_saved_threat_urls(urls)
            trackers = data.get("trackers", [])
            if isinstance(trackers, list):
                self.tracker_domains = parse_domain_feed(
                    "\n".join(str(domain) for domain in trackers)
                )
            return parse_domain_feed("\n".join(str(domain) for domain in domains))
        except FileNotFoundError:
            return set()
        except (OSError, ValueError, TypeError) as error:
            print(f"Could not load the saved threat list: {error}", file=sys.stderr)
            return set()

    def open_settings(self):
        index = self.tabs.indexOf(self.settings_page)
        if index == -1:
            index = self.tabs.addTab(self.settings_page, "Settings")
        self.tabs.setCurrentIndex(index)

    def save_general_settings(self):
        text = self.homepage_input.text().strip()
        home_url = normalize_home_url(text)
        if home_url is None:
            self.statusBar().showMessage("Enter a valid HTTP or HTTPS homepage URL", 5000)
            self.homepage_input.setFocus()
            return
        self.home_url = home_url
        self.homepage_input.setText(home_url)
        self.search_engine = self.search_engine_combo.currentText()
        self.preferences.setValue("home_url", self.home_url)
        self.preferences.setValue("search_engine", self.search_engine)
        self.site_exceptions = parse_site_list(self.site_exceptions_input.toPlainText())
        self.preferences.setValue("site_exceptions", "\n".join(sorted(self.site_exceptions)))
        self.statusBar().showMessage("Settings saved", 3000)

    def set_javascript_enabled(self, enabled):
        self.javascript_enabled = enabled
        self.preferences.setValue("javascript_enabled", enabled)
        for index in range(self.tabs.count()):
            view = self.tabs.widget(index)
            if isinstance(view, QWebEngineView):
                view.settings().setAttribute(
                    QWebEngineSettings.WebAttribute.JavascriptEnabled, enabled
                )

    def set_dark_mode(self, enabled):
        self.dark_mode_enabled = enabled
        self.preferences.setValue("dark_mode_enabled", enabled)
        for index in range(self.tabs.count()):
            view = self.tabs.widget(index)
            if isinstance(view, QWebEngineView):
                view.settings().setAttribute(
                    QWebEngineSettings.WebAttribute.ForceDarkMode, enabled
                )

    def set_tracking_protection(self, enabled):
        self.tracking_protection_enabled = enabled
        self.interceptor.tracking_protection_enabled = enabled
        self.preferences.setValue("tracking_protection_enabled", enabled)

    def set_threat_protection(self, enabled):
        self.threat_protection_enabled = enabled
        self.interceptor.threat_protection_enabled = enabled
        self.preferences.setValue("threat_protection_enabled", enabled)

    def refresh_threat_list_status(self):
        updated = self.preferences.value("threat_list_updated", "")
        total = len(self.threat_domains) + len(self.threat_urls) + len(self.tracker_domains)
        if total:
            message = (
                f"{len(self.threat_domains):,} blocked domains · "
                f"{len(self.threat_urls):,} blocked URLs · "
                f"{len(self.tracker_domains):,} tracker domains"
            )
            if updated:
                message += f" · Last updated {updated}"
        else:
            message = "No threat list downloaded yet. Update the lists to enable domain matching."
        self.threat_list_status.setText(message)

    def update_threat_feeds(self):
        if self.feed_thread and self.feed_thread.isRunning():
            return
        self.update_feeds_button.setEnabled(False)
        self.threat_list_status.setText("Downloading threat lists…")
        thread = ThreatFeedUpdateThread(self)
        self.feed_thread = thread
        thread.feeds_updated.connect(self.accept_threat_feeds)
        thread.update_failed.connect(self.threat_feed_update_failed)
        thread.finished.connect(self.threat_feed_thread_finished)
        thread.start()

    def accept_threat_feeds(self, threat_list):
        domains = set(threat_list["domains"])
        urls = set(threat_list["urls"])
        trackers = set(threat_list.get("trackers", ()))
        try:
            self.threat_list_path.parent.mkdir(parents=True, exist_ok=True)
            temporary_path = self.threat_list_path.with_suffix(".tmp")
            temporary_path.write_text(
                json.dumps(
                    {
                        "domains": sorted(domains),
                        "urls": sorted(urls),
                        "trackers": sorted(trackers),
                    },
                    separators=(",", ":"),
                ),
                encoding="utf-8",
            )
            temporary_path.replace(self.threat_list_path)
        except OSError as error:
            self.threat_list_status.setText(f"Could not save threat lists: {error}")
            self.statusBar().showMessage("Threat list update could not be saved", 5000)
            return
        self.threat_domains = set(domains)
        self.threat_urls = set(urls)
        self.interceptor.threat_domains = frozenset(domains)
        self.interceptor.threat_urls = frozenset(urls)
        self.tracker_domains = set(trackers)
        self.interceptor.tracker_domains = frozenset(trackers)
        from datetime import datetime, timezone

        updated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        self.preferences.setValue("threat_list_updated", updated)
        self.refresh_threat_list_status()
        errors = threat_list.get("errors", [])
        if errors:
            self.threat_list_status.setText(
                f"{len(domains):,} blocked domains · {len(urls):,} blocked URLs · "
                f"{len(trackers):,} tracker domains · "
                f"{len(errors)} feed(s) failed; first error: {errors[0]}"
            )
            self.statusBar().showMessage(
                f"Threat lists partially updated; {len(errors)} feed(s) failed",
                8000,
            )
        else:
            self.statusBar().showMessage(
                f"Lists updated ({len(domains):,} threat domains, {len(urls):,} URLs, "
                f"{len(trackers):,} tracker domains)",
                5000,
            )

    def threat_feed_update_failed(self, error):
        self.threat_list_status.setText(f"Threat list update failed: {error}")
        self.statusBar().showMessage("Could not update threat lists", 5000)

    def threat_feed_thread_finished(self):
        self.update_feeds_button.setEnabled(True)
        self.feed_thread = None

    def show_interstitial(self, view, url, html_text):
        self.interstitial_urls[view] = url.toString()
        view.setHtml(html_text)
        if view is self.active_view():
            self.url_bar.setText(url.toString())

    def show_threat_page(self, view, url):
        host = html.escape(url.host())
        self.show_interstitial(
            view,
            url,
            interstitial_html(
                "Blocked website",
                "Blocked: suspected phishing or malware",
                f"<p><b>{host}</b> is on a phishing/malware list, so Flame Darkness "
                "stopped the page before it loaded.</p>",
                [("Go to homepage", self.home_url, "primary")],
            ),
        )

    def handle_http_blocked(self, view, url):
        if url.port(-1) != -1:
            self.show_http_warning(view, url)
            return
        secure = QUrl(url)
        secure.setScheme("https")
        self.upgrade_attempts[view] = url
        view.setUrl(secure)

    def show_http_warning(self, view, url):
        host = html.escape(url.host())
        proceed = f"https://{BrowserPage.ALLOW_HTTP_HOST}/?u=" + quote(url.toString(), safe="")
        self.show_interstitial(
            view,
            url,
            interstitial_html(
                "Connection not secure",
                "No secure connection available",
                f"<p><b>{host}</b> could not be reached over HTTPS. Over plain HTTP, "
                "anyone on the network can read or change what you send and receive.</p>",
                [
                    ("Go to homepage", self.home_url, "primary"),
                    ("Continue over HTTP", proceed, "danger"),
                ],
            ),
        )

    def show_blocked_site(self, host):
        self.statusBar().showMessage(
            f"Blocked potentially malicious website: {host}", 10000
        )

    def closeEvent(self, event):
        if self.feed_thread and self.feed_thread.isRunning():
            self.feed_thread.requestInterruption()
            if not self.feed_thread.wait(20000):
                self.feed_thread.terminate()
                self.feed_thread.wait()
        # Pages must be destroyed before the profile they belong to.
        for index in reversed(range(self.tabs.count())):
            widget = self.tabs.widget(index)
            self.tabs.removeTab(index)
            if isinstance(widget, QWebEngineView):
                widget.setParent(None)
                sip.delete(widget)
        super().closeEvent(event)

    @staticmethod
    def _button(text, callback):
        from PyQt6.QtWidgets import QPushButton

        button = QPushButton(text)
        button.setFlat(True)
        button.clicked.connect(callback)
        return button

    def _add_shortcuts(self):
        shortcuts = (
            ("Ctrl+L", self.focus_address_bar),
            ("Ctrl+T", lambda: self.add_tab(self.home_url)),
            ("Ctrl+W", self.close_current_tab),
            ("Ctrl+R", self.active_view_reload),
            ("Ctrl+F", self.open_find),
            ("Ctrl+D", self.add_bookmark),
            ("Alt+Left", self.active_view_back),
            ("Alt+Right", self.active_view_forward),
            ("Ctrl+,", self.open_settings),
        )
        for key, callback in shortcuts:
            shortcut = QShortcut(QKeySequence(key), self)
            shortcut.activated.connect(callback)
            self.shortcuts.append(shortcut)

    def add_tab(self, url=None, blank=False):
        view = QWebEngineView()
        page = BrowserPage(
            self.profile, view, self.interceptor, lambda: self.site_exceptions
        )
        view.setPage(page)
        page.threatBlocked.connect(self.show_blocked_site)
        page.permissionDenied.connect(self.show_permission_denied)
        # Deferred: loading content from inside acceptNavigationRequest crashes Qt.
        page.mainFrameThreat.connect(
            lambda url, browser=view: QTimer.singleShot(
                0, lambda: self.show_threat_page(browser, url)
            )
        )
        page.httpBlocked.connect(
            lambda url, browser=view: QTimer.singleShot(
                0, lambda: self.handle_http_blocked(browser, url)
            )
        )
        page.newWindowRequested.connect(self.handle_new_window)
        page.fullScreenRequested.connect(self.handle_fullscreen)

        settings = view.settings()
        settings.setAttribute(
            QWebEngineSettings.WebAttribute.ForceDarkMode, self.dark_mode_enabled
        )
        settings.setAttribute(QWebEngineSettings.WebAttribute.WebRTCPublicInterfacesOnly, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.FullScreenSupportEnabled, True)
        for attribute in (
            QWebEngineSettings.WebAttribute.AllowRunningInsecureContent,
            QWebEngineSettings.WebAttribute.AllowGeolocationOnInsecureOrigins,
            QWebEngineSettings.WebAttribute.ReadingFromCanvasEnabled,
            QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls,
            QWebEngineSettings.WebAttribute.LocalContentCanAccessFileUrls,
            QWebEngineSettings.WebAttribute.JavascriptCanAccessClipboard,
        ):
            settings.setAttribute(attribute, False)
        settings.setAttribute(
            QWebEngineSettings.WebAttribute.JavascriptEnabled,
            self.javascript_enabled,
        )

        index = self.tabs.addTab(view, "New Tab")
        self.tabs.setCurrentIndex(index)
        view.urlChanged.connect(lambda url, browser=view: self.page_url_changed(browser, url))
        view.titleChanged.connect(lambda title, browser=view: self.page_title_changed(browser, title))
        view.loadProgress.connect(lambda value, browser=view: self.page_load_progress(browser, value))
        view.loadFinished.connect(lambda ok, browser=view: self.page_load_finished(browser, ok))
        view.loadStarted.connect(lambda browser=view: self.page_load_started(browser))
        if url:
            view.setUrl(QUrl(url))
        elif not blank:
            view.setUrl(QUrl(self.home_url))
        return view

    def handle_new_window(self, request):
        # Only honour popups/new tabs that follow a real user action.
        if not request.isUserInitiated():
            self.statusBar().showMessage(
                f"Blocked a pop-up from {request.requestedUrl().host() or 'a page'}", 5000
            )
            return
        view = self.add_tab(blank=True)
        request.openIn(view.page())

    def handle_fullscreen(self, request):
        request.accept()
        chrome = (
            self.navigation_toolbar,
            self.tools_toolbar,
            self.tabs.tabBar(),
            self.statusBar(),
        )
        if request.toggleOn():
            self._maximized_before_fullscreen = self.isMaximized()
            for widget in chrome:
                widget.hide()
            self.showFullScreen()
        else:
            for widget in chrome:
                widget.show()
            if getattr(self, "_maximized_before_fullscreen", False):
                self.showMaximized()
            else:
                self.showNormal()

    def show_permission_denied(self, host, kind):
        self.statusBar().showMessage(
            f"Denied {kind} request from {host or 'a page'}", 5000
        )

    def active_view(self):
        current = self.tabs.currentWidget()
        return current if isinstance(current, QWebEngineView) else None

    def active_view_back(self):
        if self.active_view():
            self.active_view().back()

    def active_view_forward(self):
        if self.active_view():
            self.active_view().forward()

    def active_view_reload(self):
        if self.active_view():
            self.active_view().reload()

    def go_home(self):
        view = self.active_view()
        if view:
            view.setUrl(QUrl(self.home_url))
        else:
            self.add_tab(self.home_url)

    def navigate_to_url(self):
        text = self.url_bar.text().strip()
        if not text:
            return
        view = self.active_view() or self.add_tab(self.home_url)
        if any(char.isspace() for char in text) or (
            "." not in text and not text.startswith(("localhost", "http://", "https://"))
        ):
            search_urls = {
                "Google": "https://www.google.com/search?",
                "DuckDuckGo": "https://duckduckgo.com/?",
                "Bing": "https://www.bing.com/search?",
            }
            url = search_urls.get(self.search_engine, search_urls["Google"])
            view.setUrl(QUrl(url + urlencode({"q": text})))
            return
        if "://" not in text and not text.startswith("localhost"):
            text = "https://" + text
        view.setUrl(QUrl.fromUserInput(text))

    def page_url_changed(self, view, url):
        if url.scheme() in ("data", "about") and view in self.interstitial_urls:
            if view is self.active_view():
                self.url_bar.setText(self.interstitial_urls[view])
            return
        self.interstitial_urls.pop(view, None)
        if view is not self.active_view():
            return
        self.url_bar.setText(url.toString())
        self.bookmark_action.setText(
            "★" if any(item["url"] == url.toString() for item in self.bookmarks) else "☆"
        )
        if url.scheme() in ("http", "https") and url.host():
            self.history.insert(0, {"title": url.host(), "url": url.toString()})
            self.history = self.history[:100]

    def page_title_changed(self, view, title):
        index = self.tabs.indexOf(view)
        if index != -1:
            self.tabs.setTabText(index, (title or "New Tab")[:28])
            self.tabs.setTabToolTip(index, title or view.url().toString())
            if view is self.active_view():
                self.setWindowTitle(f"{title or 'New Tab'} — Flame Darkness 1.0")

    def page_load_started(self, view):
        if view is self.active_view():
            self.progress.setValue(0)
            self.progress.show()

    def page_load_progress(self, view, value):
        if view is self.active_view():
            self.progress.setValue(value)

    def page_load_finished(self, view, ok):
        attempted = self.upgrade_attempts.get(view)
        current = view.url()
        if attempted is not None and current.scheme() == "https":
            if ok:
                self.upgrade_attempts.pop(view, None)
            elif current.host().lower() == attempted.host().lower():
                self.upgrade_attempts.pop(view, None)
                self.show_http_warning(view, attempted)
                return
        elif not ok and current.scheme() in ("http", "https") and (
            self.threat_protection_enabled
            and url_is_blocked(current, self.threat_domains, self.threat_urls)
        ):
            # A redirect or sub-navigation into a listed site was blocked.
            self.show_threat_page(view, current)
            return
        if view is self.active_view():
            self.progress.hide()
            self.statusBar().showMessage(
                "Page loaded" if ok else "Could not load page", 3000
            )

    def sync_active_tab(self, _index):
        view = self.active_view()
        if not view:
            self.url_bar.clear()
            self.bookmark_action.setText("☆")
            self.setWindowTitle("Settings — Flame Darkness")
            return
        self.url_bar.setText(view.url().toString())
        self.setWindowTitle(f"{view.title() or 'New Tab'} — Flame Darkness")
        self.bookmark_action.setText(
            "★" if any(item["url"] == view.url().toString() for item in self.bookmarks) else "☆"
        )

    def close_tab(self, index):
        view = self.tabs.widget(index)
        self.upgrade_attempts.pop(view, None)
        self.interstitial_urls.pop(view, None)
        self.tabs.removeTab(index)
        if view is not self.settings_page:
            view.deleteLater()
        if self.tabs.count() == 0:
            self.add_tab(self.home_url)

    def close_current_tab(self):
        index = self.tabs.currentIndex()
        if index >= 0:
            self.close_tab(index)

    def add_bookmark(self):
        view = self.active_view()
        if not view or not view.url().host():
            return
        url = view.url().toString()
        if any(item["url"] == url for item in self.bookmarks):
            self.bookmarks = [item for item in self.bookmarks if item["url"] != url]
            self.bookmark_action.setText("☆")
            self.statusBar().showMessage("Bookmark removed", 2000)
        else:
            self.bookmarks.insert(0, {"title": view.title() or view.url().host(), "url": url})
            self.bookmark_action.setText("★")
            self.statusBar().showMessage("Bookmark added", 2000)

    def show_bookmarks(self):
        menu = QMenu(self)
        if not self.bookmarks:
            menu.addAction("No bookmarks yet").setEnabled(False)
        for item in self.bookmarks:
            menu.addAction(
                item["title"],
                lambda checked=False, url=item["url"]: self.open_url_in_tab(url),
            )
        menu.exec(QCursor.pos())

    def show_history(self):
        menu = QMenu(self)
        if not self.history:
            menu.addAction("No history in this session").setEnabled(False)
        else:
            for item in self.history:
                menu.addAction(
                    item["title"],
                    lambda checked=False, url=item["url"]: self.open_url_in_tab(url),
                )
            menu.addSeparator()
            menu.addAction("Clear History", self.clear_history)
        menu.exec(self.mapToGlobal(self.rect().topLeft()))

    def open_url_in_tab(self, url):
        view = self.active_view() or self.add_tab()
        view.setUrl(QUrl(url))

    def clear_history(self):
        self.history.clear()
        self.statusBar().showMessage("Session history cleared", 2000)

    def show_downloads(self):
        menu = QMenu(self)
        if not self.downloads:
            menu.addAction("No downloads this session").setEnabled(False)
        for item in reversed(self.downloads):
            menu.addAction(f"{item['status']} · {item['name']}").setEnabled(False)
        menu.exec(QCursor.pos())

    def download_requested(self, download):
        suggested_name = download.downloadFileName() or "download"
        path, _ = QFileDialog.getSaveFileName(
            self, "Save download", suggested_name
        )
        if not path:
            download.cancel()
            return
        from pathlib import Path

        target = Path(path)
        download.setDownloadDirectory(str(target.parent))
        download.setDownloadFileName(target.name)
        item = {"name": target.name, "status": "Downloading"}
        self.downloads.append(item)
        download.accept()
        download.stateChanged.connect(lambda state: self.update_download(item, state))

    def update_download(self, item, state):
        if state == QWebEngineDownloadRequest.DownloadState.DownloadCompleted:
            item["status"] = "Finished"
        elif state in (
            QWebEngineDownloadRequest.DownloadState.DownloadCancelled,
            QWebEngineDownloadRequest.DownloadState.DownloadInterrupted,
        ):
            item["status"] = "Failed"
        else:
            item["status"] = "Downloading"
        self.statusBar().showMessage(f"{item['status']}: {item['name']}", 5000)

    def toggle_javascript(self, state):
        self.set_javascript_enabled(state == Qt.CheckState.Checked.value)

    def focus_address_bar(self):
        self.url_bar.setFocus()
        self.url_bar.selectAll()

    def open_find(self):
        self.find_bar.show()
        self.find_input.setFocus()
        self.find_input.selectAll()

    def find_in_page(self, text):
        if self.active_view():
            self.active_view().findText(text)

    def find_next(self):
        if self.active_view():
            self.active_view().findText(self.find_input.text())

    def find_previous(self):
        if self.active_view():
            self.active_view().findText(
                self.find_input.text(), QWebEnginePage.FindFlag.FindBackward
            )

    def close_find(self):
        if self.active_view():
            self.active_view().findText("")
        self.find_bar.hide()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setOrganizationName("FlameDarkness")
    app.setApplicationName("FlameDarkness")
    window = FlameDarknessWindow()
    window.show()
    sys.exit(app.exec())
