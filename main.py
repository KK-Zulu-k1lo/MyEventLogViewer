#!/usr/bin/env python3
"""
MyEventLogViewer
Real-time macOS log viewer with filter, copy, timezone, and uptime/log-count display.
"""

import sys, re, subprocess, hashlib
from datetime import datetime, timezone, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget,
    QVBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QMenu, QFileDialog, QMessageBox,
    QTextEdit, QDockWidget, QToolBar, QLabel, QComboBox,
    QHeaderView
)
from PySide6.QtCore import QThread, Signal, Qt, QTimer
from PySide6.QtGui import QFont, QColor, QKeySequence

# ─── CONFIG ───────────────────────────────────────────
MAX_ROWS    = 500
THROTTLE_MS = 500
DISCONNECT_THRESHOLD = 2000  # ms

LOG_PATTERN = re.compile(r"""
    ^(?P<timestamp>\S+\s+\S+)\s+
    (?P<host>\S+)\s+
    (?P<proc>\S+)

\[(?P<pid>\d+)\]

:\s+
    \((?P<category>\S+)\)\s+
    

\[(?P<subsys>[^\]

]+)\]

\s+
    (?P<msg>.+)$
""", re.VERBOSE)

MAIN_TABS = {
    "All":     None,
    "Error":   ["error"],
    "Warning": ["warn"],
    "Info":    []
}
ERROR_SUBTABS = {
    "Security": ["security","security_exception"],
    "WiFi":     ["corewifi","auto-join","wifi"],
    "Network":  ["network","tcp","udp","http","dns"],
    "Other":    []
}
CERT_CN = "MyEventLogViewer"

def load_public_key(common_name: str):
    pem = subprocess.check_output([
        "security", "find-certificate", "-c", common_name, "-p"
    ])
    cert = x509.load_pem_x509_certificate(pem, default_backend())
    return cert.public_key()

try:
    PUBLIC_KEY = load_public_key(CERT_CN)
except subprocess.CalledProcessError:
    PUBLIC_KEY = None
    print(f"Warning: CN='{CERT_CN}' not found. Signature disabled.", file=sys.stderr)

def verify_signature(pubkey, sig_path, file_path):
    with open(file_path, "rb") as f:
        digest = hashlib.sha256(f.read()).digest()
    sig = open(sig_path, "rb").read()
    pubkey.verify(sig, digest, padding.PKCS1v15(), hashes.SHA256())
    return True

class LogThread(QThread):
    new_line = Signal(str)
    def run(self):
        p = subprocess.Popen(
            ["log","stream","--style","syslog"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1
        )
        while True:
            line = p.stdout.readline()
            if not line:
                break
            self.new_line.emit(line.rstrip())
        p.terminate()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MyEventLogViewer")
        self.resize(1000, 600)

        font = QFont("Courier New", 11)
        QApplication.instance().setFont(font)

        # timezone
        self.local_tz = datetime.now().astimezone().tzinfo
        self.current_tz = self.local_tz
        self.current_tz_label = "Local"

        # throttle queue
        self.queue = []
        self.timer = QTimer(self)
        self.timer.setInterval(THROTTLE_MS)
        self.timer.timeout.connect(self.flush_queue)
        self.timer.start()

        # connection status timer
        self.conn_timer = QTimer(self)
        self.conn_timer.setInterval(DISCONNECT_THRESHOLD // 2)
        self.conn_timer.timeout.connect(self.check_connection)
        self.conn_timer.start()
        self.last_time_ms = int(datetime.now(timezone.utc).timestamp()*1000)

        # uptime/log-count timer
        self.info_timer = QTimer(self)
        self.info_timer.setInterval(1000)  # update every second
        self.info_timer.timeout.connect(self.update_uptime_and_count)
        self.info_timer.start()

        # counters
        self.log_count_24h = 0
        self.start_time = datetime.now(timezone.utc)

        # tabs
        self.tabs = QTabWidget()
        self.tables = {}
        self.error_sub = {}
        for name in MAIN_TABS:
            if name == "Error":
                err_tabs = QTabWidget()
                for sub in ERROR_SUBTABS:
                    tbl = self.make_table(include_action=True)
                    err_tabs.addTab(tbl, sub)
                    self.error_sub[sub] = tbl
                w = QWidget(); QVBoxLayout(w).addWidget(err_tabs)
                self.tabs.addTab(w, "Error")
            else:
                inc = name in ("Warning","Info")
                tbl = self.make_table(include_action=inc)
                self.tables[name] = tbl
                w = QWidget(); QVBoxLayout(w).addWidget(tbl)
                self.tabs.addTab(w, name)
        self.setCentralWidget(self.tabs)

        # notepad
        self.notepad = QTextEdit()
        self.notepad.setAcceptRichText(False)
        self.notepad.setPlaceholderText("Paste here…")
        dock = QDockWidget("Notepad", self)
        dock.setWidget(self.notepad)
        self.addDockWidget(Qt.RightDockWidgetArea, dock)
        self.notepad_dock = dock

        # status bar (3 rows + info row)
        bar_container = QWidget()
        bar_layout = QVBoxLayout(bar_container)
        bar_layout.setContentsMargins(0,0,0,0)
        self.st_rate = QLabel("READY")
        self.st_rate.setStyleSheet("color: green;")
        self.st_msg  = QLabel("")
        self.st_xtra = QLabel("")
        self.st_info = QLabel("")  # uptime & count
        for lbl in (self.st_rate, self.st_msg, self.st_xtra, self.st_info):
            bar_layout.addWidget(lbl)
        self.statusBar().addPermanentWidget(bar_container,1)

        # toolbar: toggle notepad, tz, filter
        tb = QToolBar("View", self)
        self.addToolBar(Qt.TopToolBarArea, tb)
        tog = tb.addAction("Toggle Notepad")
        tog.setCheckable(True); tog.setChecked(True)
        tog.toggled.connect(self.notepad_dock.setVisible)

        self.tz_cb = QComboBox()
        self.tz_cb.addItems(["Local","UTC"])
        self.tz_cb.currentIndexChanged.connect(self.change_tz)
        tb.addWidget(self.tz_cb)

        self.range_cb = QComboBox()
        self.range_cb.addItems(["All","Last 1m","Last 10s"])
        self.range_cb.currentIndexChanged.connect(self.apply_filter)
        tb.addWidget(self.range_cb)

        # start thread
        self.thread = LogThread()
        self.thread.new_line.connect(self.on_line)
        self.thread.start()

    def change_tz(self, idx):
        if idx==0:
            self.current_tz = self.local_tz
            self.current_tz_label = "Local"
        else:
            self.current_tz = timezone.utc
            self.current_tz_label = "UTC"
        self.st_msg.setText(f"TZ: {self.current_tz_label}")
        QTimer.singleShot(2000, lambda: self.st_msg.clear())

    def make_table(self, include_action: bool):
        cols = 6 if include_action else 5
        hdrs = (["Action","Timestamp","Proc[PID]","Category","Subsystem","Message"]
                if include_action else
                ["Timestamp","Proc[PID]","Category","Subsystem","Message"])
        tbl = QTableWidget(0, cols)
        tbl.setWordWrap(False)
        tbl.setHorizontalHeaderLabels(hdrs)
        tbl.setShowGrid(False)
        tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        tbl.verticalHeader().setDefaultSectionSize(24)
        off = 0
        if include_action:
            tbl.setColumnWidth(0,70); off=1
        tbl.setColumnWidth(off,200); tbl.setColumnWidth(off+1,180); tbl.setColumnWidth(off+2,100)
        tbl.horizontalHeader().setSectionResizeMode(off+3, QHeaderView.Stretch)
        if include_action:
            tbl.setColumnHidden(tbl.columnCount()-1,True)
        tbl.setContextMenuPolicy(Qt.CustomContextMenu)
        tbl.customContextMenuRequested.connect(lambda pos,t=tbl: self.ctx_menu(t,pos))
        tbl.keyPressEvent = lambda e,t=tbl: self.keypress(e,t)
        tbl.has_action = include_action
        tbl.timestamps = []
        return tbl

    def on_line(self, raw: str):
        now_ms = int(datetime.now(timezone.utc).timestamp()*1000)
        self.last_time_ms = now_ms
        # increment 24h log count
        self.log_count_24h += 1

        m = LOG_PATTERN.match(raw)
        if not m: return
        d = m.groupdict(); low = raw.lower()
        self.queue.append((self.tables["All"], d, False))
        if any(k in low for k in MAIN_TABS["Warning"]):
            self.queue.append((self.tables["Warning"], d, False))
        elif not any(k in low for k in MAIN_TABS["Error"]+MAIN_TABS["Warning"]):
            self.queue.append((self.tables["Info"], d, False))
        if any(k in low for k in MAIN_TABS["Error"]):
            placed=False
            for sub,keys in ERROR_SUBTABS.items():
                if sub!="Other" and any(k in low for k in keys):
                    self.queue.append((self.error_sub[sub], d, sub=="Security"))
                    placed=True; break
            if not placed:
                self.queue.append((self.error_sub["Other"], d, False))

    def flush_queue(self):
        if not self.queue: return
        tbl, d, alert = self.queue.pop(0)
        self.append_row(tbl, d, alert)
        self.update_connection_status()

    def append_row(self, tbl, d, alert: bool):
        tbl.setUpdatesEnabled(False)
        orig = d["timestamp"]
        try: dt = datetime.fromisoformat(orig)
        except:
            base = orig.split("+")[0]
            dt = datetime.strptime(base, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
        dt_u = dt.astimezone(timezone.utc)
        tbl.timestamps.append(dt_u)
        disp = dt.astimezone(self.current_tz)
        ts = disp.strftime(f"[{self.current_tz_label}]%m/%d %H:%M:%S")
        row = tbl.rowCount(); tbl.insertRow(row)
        off = tbl.has_action and 1 or 0
        if tbl.has_action:
            btn=QPushButton("Copy"); tbl.setCellWidget(row,0,btn)
            btn.clicked.connect(lambda _,r=row,t=tbl:self.copy_row(r,t))
        vals=[ts,f"{d['proc']}[{d['pid']}]",d['category'],d['subsys'],d['msg']]
        for i,txt in enumerate(vals): tbl.setItem(row, off+i, QTableWidgetItem(txt))
        tbl.resizeRowToContents(row)
        if tbl.rowCount()>MAX_ROWS: tbl.removeRow(0); tbl.timestamps.pop(0)
        clr=QColor("white")
        if tbl in self.error_sub.values(): clr=QColor("red")
        elif tbl is self.tables["Warning"]: clr=QColor("yellow")
        elif tbl is self.tables["Info"]: clr=QColor("green")
        for c in range(tbl.columnCount()):
            it=tbl.item(row,c)
            if it: it.setForeground(clr)
        if alert: QApplication.beep()
        tbl.setUpdatesEnabled(True)
        self.apply_filter(self.range_cb.currentIndex())

    def copy_row(self,row,tbl):
        parts=[];start=tbl.has_action and 1 or 0
        for c in range(start,tbl.columnCount()):
            it=tbl.item(row,c); parts.append(it.text() if it else "")
        self.notepad.append("\t".join(parts))
        self.st_msg.setText("message clipped")
        QTimer.singleShot(2000, lambda:self.st_msg.clear())

    def apply_filter(self,idx=0):
        cutoff=None; now_u=datetime.now(timezone.utc)
        if idx==1: cutoff=now_u-timedelta(minutes=1)
        elif idx==2: cutoff=now_u-timedelta(seconds=10)
        for tbl in list(self.tables.values())+list(self.error_sub.values()):
            for r,ts in enumerate(tbl.timestamps):
                tbl.setRowHidden(r,bool(cutoff and ts<cutoff))

    def check_connection(self):
        now_ms=int(datetime.now(timezone.utc).timestamp()*1000)
        if now_ms-self.last_time_ms>DISCONNECT_THRESHOLD:
            self.st_rate.setText("DISCONNECTED")
            self.st_rate.setStyleSheet("color: red;")
        else:
            self.st_rate.setText("READY")
            self.st_rate.setStyleSheet("color: green;")

    def update_connection_status(self):
        # called after flush_queue to immediately update
        self.check_connection()

    def update_uptime_and_count(self):
        uptime = datetime.now(timezone.utc)-self.start_time
        h,m,s = uptime.seconds//3600, (uptime.seconds%3600)//60, uptime.seconds%60
        self.st_info.setText(f"SYSTEM UPTIME: {h:02d}:{m:02d}:{s:02d}   LOGS(24h): {self.log_count_24h}")

    def ctx_menu(self,tbl,pos):
        menu=QMenu(); ca=menu.addAction("Copy Selected"); vs=menu.addAction("Verify Signature")
        act=menu.exec_(tbl.viewport().mapToGlobal(pos))
        if act==ca: self.copy_selection(tbl)
        elif act==vs: self.verify_dialog()

    def keypress(self,ev,tbl):
        if ev.matches(QKeySequence.Copy): self.copy_selection(tbl)
        else: super(type(tbl),tbl).keyPressEvent(ev)

    def copy_selection(self,tbl):
        idxs=tbl.selectedIndexes()
        if not idxs: return
        idxs.sort(key=lambda x:(x.row(), x.column()))
        lines, rd, last=[], [], -1
        for idx in idxs:
            if idx.row()!=last:
                if rd: lines.append("\t".join(rd))
                rd,last=[], idx.row()
            rd.append(tbl.item(idx.row(), idx.column()).text())
        if rd: lines.append("\t".join(rd))
        QApplication.clipboard().setText("\n".join(lines))

    def verify_dialog(self):
        if not PUBLIC_KEY:
            QMessageBox.critical(self,"Signature Error",f"Cert '{CERT_CN}' not found."); return
        sf,_=QFileDialog.getOpenFileName(self,"Select Signature")
        df,_=QFileDialog.getOpenFileName(self,"Select File to Verify")
        if not(sf and df):return
        try:
            ok=verify_signature(PUBLIC_KEY,sf,df)
            QMessageBox.information(self,"Signature","Valid" if ok else "Invalid")
        except Exception as e:
            QMessageBox.critical(self,"Signature Exception",str(e))

    def closeEvent(self,ev):
        self.thread.stop()
        super().closeEvent(ev)

if __name__=="__main__":
    app=QApplication(sys.argv)
    w=MainWindow()
    w.show()
    sys.exit(app.exec())

