# Domain Mirror v5.0 - Burp Suite Extension
# 
# Features:
# - CONFIGURABLE AUTH MODE PER DOMAIN
# - Auto-capture from browser login
# - Dynamic domain configuration (unlimited)
# - Custom header support (API keys, etc.)
# - Full JWT refresh handling
# - FULL RESPONSE DIFF VIEW WITH HIGHLIGHTING (v5.0)
#
# Auth Modes:
# - Auto: Detect and use whatever is found
# - Cookies Only: Only swap cookies
# - Bearer Only: Only swap Authorization header
# - Both: Swap both cookies and bearer
# - None: Don't swap any auth (for public endpoints)
# - Custom Header: Use a custom header (e.g., X-API-Key)
#
# Author: Claude
# Version: 5.0

from burp import IBurpExtender, ITab, IProxyListener, IHttpListener
from javax.swing import (JPanel, JTable, JScrollPane, JButton, JTextField, JLabel, 
                         JTabbedPane, JSplitPane, JTextArea, BoxLayout, BorderFactory,
                         JCheckBox, SwingConstants, JOptionPane, SwingUtilities,
                         ListSelectionModel, JComboBox, JDialog, JFrame, JTextPane,
                         JFileChooser, RowSorter, SortOrder)
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer, TableRowSorter
from javax.swing.text import StyleConstants, SimpleAttributeSet, StyleContext
from javax.swing.filechooser import FileNameExtensionFilter
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Color, Font, FlowLayout, Dimension, GridLayout
from java.util import ArrayList, Comparator
from threading import Thread, Lock
import java.io
import hashlib
import json
import time
import base64
import difflib


# Auth mode constants
AUTH_AUTO = "Auto Detect"
AUTH_COOKIES = "Cookies Only"
AUTH_BEARER = "Bearer Only"
AUTH_BOTH = "Cookies + Bearer"
AUTH_NONE = "None"
AUTH_CUSTOM = "Custom Header"

AUTH_MODES = [AUTH_AUTO, AUTH_COOKIES, AUTH_BEARER, AUTH_BOTH, AUTH_NONE, AUTH_CUSTOM]

# Burp tool flag constants
TOOL_PROXY = 0x00000004
TOOL_SCANNER = 0x00000010
TOOL_INTRUDER = 0x00000020
TOOL_REPEATER = 0x00000040
TOOL_EXTENDER = 0x00000400


class BurpExtender(IBurpExtender, ITab, IProxyListener, IHttpListener):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Domain Mirror v5")
        
        # Domain list structure:
        # {
        #   "domain": "example.com",
        #   "is_primary": True,
        #   "auth_mode": AUTH_AUTO,
        #   "custom_header_name": "",    # e.g., "X-API-Key"
        #   "custom_header_value": "",   # e.g., "abc123"
        #   "session": {
        #       "cookies": {},
        #       "bearer": "",
        #       "refresh_token": "",
        #       "token_expiry": None,
        #       "last_updated": None,
        #       "status": "waiting"
        #   }
        # }
        self.domains = ArrayList()
        self.domains_lock = Lock()
        
        # Configuration
        self.login_patterns = [
            "/login", "/signin", "/auth", "/authenticate", "/oauth", 
            "/token", "/session", "/api/login", "/api/auth", "/api/token"
        ]
        self.refresh_patterns = ["/refresh", "/token/refresh", "/auth/refresh"]
        self.token_keys = ["access_token", "accessToken", "token", "id_token", "jwt", "bearer"]
        self.refresh_token_keys = ["refresh_token", "refreshToken"]
        
        # Results
        self.results = ArrayList()
        self.results_lock = Lock()
        
        # Flags
        self.capture_enabled = True
        self.mirror_enabled = False
        self.auto_refresh_mirrors = True
        self.debug_mode = False  # Disabled by default - enable in Logs tab
        
        # Tool interception flags (which tools to mirror from)
        self.mirror_from_proxy = True      # Always on by default
        self.mirror_from_repeater = False
        self.mirror_from_scanner = False
        self.mirror_from_intruder = False
        self.mirror_from_extender = False
        
        # Pending refresh
        self.pending_refresh = set()
        self.pending_refresh_lock = Lock()
        
        # Track our own mirror requests to prevent infinite loops
        self._our_mirror_requests = set()
        self._our_requests_lock = Lock()
        
        # Safeguards against resource exhaustion
        self._max_results = 1000  # Maximum number of results to keep
        self._active_mirror_threads = 0
        self._max_concurrent_mirrors = 10  # Maximum concurrent mirror threads
        self._mirror_thread_lock = Lock()
        self._request_timeout = 15  # Seconds to wait for mirror responses
        self._max_diff_lines = 500  # Maximum lines to show in diff view
        
        # Build UI
        self._build_ui()
        
        # Register listeners
        callbacks.registerProxyListener(self)
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        
        self._log("Extension loaded! Add domains and configure auth modes.")
    
    def _build_ui(self):
        """Build main UI"""
        self._main_panel = JPanel(BorderLayout())
        self._tabs = JTabbedPane()
        
        self._tabs.addTab("Domains", self._build_domains_panel())
        self._tabs.addTab("Results", self._build_results_panel())
        self._tabs.addTab("Settings", self._build_settings_panel())
        self._tabs.addTab("Logs", self._build_log_panel())
        
        self._main_panel.add(self._tabs, BorderLayout.CENTER)
    
    def _build_domains_panel(self):
        """Build domain management panel"""
        panel = JPanel(BorderLayout(10, 10))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # Instructions
        help_panel = JPanel(BorderLayout())
        help_panel.setBorder(BorderFactory.createTitledBorder("Quick Start"))
        
        help_text = JTextArea(
            "1. Click 'Add Domain' to add domains with their auth configuration\n"
            "2. Browse to each domain and log in - sessions are captured automatically\n"
            "3. When all domains show READY, check 'Enable Mirroring'\n"
            "4. Browse the PRIMARY domain - requests mirror to all others\n\n"
            "AUTH MODES: Auto (detect), Cookies Only, Bearer Only, Both, None, Custom Header"
        )
        help_text.setEditable(False)
        help_text.setBackground(panel.getBackground())
        help_text.setFont(Font("Dialog", Font.PLAIN, 12))
        help_panel.add(help_text)
        
        panel.add(help_panel, BorderLayout.NORTH)
        
        # Domain table
        self._domain_model = DomainTableModel(self)
        self._domain_table = JTable(self._domain_model)
        self._domain_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._domain_table.setRowHeight(25)
        
        # Renderers
        self._domain_table.getColumnModel().getColumn(2).setCellRenderer(AuthModeCellRenderer())
        self._domain_table.getColumnModel().getColumn(3).setCellRenderer(StatusCellRenderer())
        
        # Column widths
        self._domain_table.getColumnModel().getColumn(0).setPreferredWidth(60)   # Primary
        self._domain_table.getColumnModel().getColumn(1).setPreferredWidth(200)  # Domain
        self._domain_table.getColumnModel().getColumn(2).setPreferredWidth(120)  # Auth Mode
        self._domain_table.getColumnModel().getColumn(3).setPreferredWidth(80)   # Status
        self._domain_table.getColumnModel().getColumn(4).setPreferredWidth(180)  # Session Info
        self._domain_table.getColumnModel().getColumn(5).setPreferredWidth(100)  # Last Updated
        
        self._domain_table.getSelectionModel().addListSelectionListener(lambda e: self._on_domain_selected())
        
        table_scroll = JScrollPane(self._domain_table)
        
        # Domain buttons
        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        add_btn = JButton("Add Domain")
        add_btn.addActionListener(lambda e: self._show_add_domain_dialog())
        btn_panel.add(add_btn)
        
        edit_btn = JButton("Edit Selected")
        edit_btn.addActionListener(lambda e: self._show_edit_domain_dialog())
        btn_panel.add(edit_btn)
        
        remove_btn = JButton("Remove")
        remove_btn.addActionListener(lambda e: self._remove_domain())
        btn_panel.add(remove_btn)
        
        primary_btn = JButton("Set Primary")
        primary_btn.addActionListener(lambda e: self._set_primary())
        btn_panel.add(primary_btn)
        
        clear_btn = JButton("Clear Session")
        clear_btn.addActionListener(lambda e: self._clear_selected_session())
        btn_panel.add(clear_btn)
        
        # Main controls
        control_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        self._mirror_checkbox = JCheckBox("Enable Mirroring")
        self._mirror_checkbox.setFont(Font("Dialog", Font.BOLD, 12))
        self._mirror_checkbox.addActionListener(lambda e: self._toggle_mirroring())
        control_panel.add(self._mirror_checkbox)
        
        clear_results_btn = JButton("Clear Results")
        clear_results_btn.addActionListener(lambda e: self._clear_results())
        control_panel.add(clear_results_btn)
        
        refresh_btn = JButton("Refresh All Sessions")
        def start_refresh():
            t = Thread(target=self._refresh_all_sessions)
            t.daemon = True
            t.start()
        refresh_btn.addActionListener(lambda e: start_refresh())
        control_panel.add(refresh_btn)
        
        test_btn = JButton("Test Mirror (Manual)")
        test_btn.addActionListener(lambda e: self._test_mirror_manual())
        test_btn.setToolTipText("Manually test mirroring to verify connectivity")
        control_panel.add(test_btn)
        
        # Session detail
        detail_panel = JPanel(BorderLayout())
        detail_panel.setBorder(BorderFactory.createTitledBorder("Session Details"))
        
        self._session_detail = JTextArea(12, 50)
        self._session_detail.setEditable(False)
        self._session_detail.setFont(Font("Monospaced", Font.PLAIN, 11))
        detail_panel.add(JScrollPane(self._session_detail))
        
        # Layout
        buttons_combined = JPanel(BorderLayout())
        buttons_combined.add(btn_panel, BorderLayout.NORTH)
        buttons_combined.add(control_panel, BorderLayout.SOUTH)
        
        center = JPanel(BorderLayout())
        center.add(table_scroll, BorderLayout.CENTER)
        center.add(detail_panel, BorderLayout.SOUTH)
        
        panel.add(center, BorderLayout.CENTER)
        panel.add(buttons_combined, BorderLayout.SOUTH)
        
        return panel
    
    def _show_add_domain_dialog(self):
        """Show dialog to add new domain"""
        dialog = DomainConfigDialog(self._main_panel, "Add Domain", self)
        dialog.setVisible(True)
        
        if dialog.result:
            self._add_domain_entry(dialog.result)
    
    def _show_edit_domain_dialog(self):
        """Show dialog to edit selected domain"""
        row = self._domain_table.getSelectedRow()
        if row < 0:
            JOptionPane.showMessageDialog(self._main_panel, "Select a domain first")
            return
        
        with self.domains_lock:
            if row >= self.domains.size():
                return
            entry = self.domains.get(row)
        
        dialog = DomainConfigDialog(self._main_panel, "Edit Domain", self, entry)
        dialog.setVisible(True)
        
        if dialog.result:
            with self.domains_lock:
                # Update entry
                entry["domain"] = dialog.result["domain"]
                entry["auth_mode"] = dialog.result["auth_mode"]
                entry["custom_header_name"] = dialog.result.get("custom_header_name", "")
                entry["custom_header_value"] = dialog.result.get("custom_header_value", "")
            
            self._domain_model.fireTableDataChanged()
            self._log("Updated domain: " + entry["domain"])
    
    def _add_domain_entry(self, config):
        """Add domain with config"""
        domain = config["domain"].strip().lower()
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        
        if not domain:
            return
        
        self._debug_print("Adding domain: '" + domain + "'")
        
        with self.domains_lock:
            # Check duplicate
            for i in range(self.domains.size()):
                if self.domains.get(i)["domain"] == domain:
                    JOptionPane.showMessageDialog(self._main_panel, "Domain already exists!")
                    return
            
            is_primary = self.domains.size() == 0
            
            new_entry = {
                "domain": domain,
                "is_primary": is_primary,
                "auth_mode": config.get("auth_mode", AUTH_AUTO),
                "custom_header_name": config.get("custom_header_name", ""),
                "custom_header_value": config.get("custom_header_value", ""),
                "session": {
                    "cookies": {},
                    "bearer": "",
                    "refresh_token": "",
                    "token_expiry": None,
                    "last_updated": None,
                    "status": "waiting"
                }
            }
            
            self.domains.add(new_entry)
            self._debug_print("Domain added. Total domains: " + str(self.domains.size()))
        
        self._domain_model.fireTableDataChanged()
        self._log("Added domain: " + domain + " [" + config.get("auth_mode", AUTH_AUTO) + "]")
    
    def _remove_domain(self):
        """Remove selected domain"""
        row = self._domain_table.getSelectedRow()
        if row < 0:
            return
        
        with self.domains_lock:
            if row < self.domains.size():
                removed = self.domains.remove(row)
                self._log("Removed: " + removed["domain"])
                
                if removed["is_primary"] and self.domains.size() > 0:
                    self.domains.get(0)["is_primary"] = True
        
        self._domain_model.fireTableDataChanged()
    
    def _set_primary(self):
        """Set selected as primary"""
        row = self._domain_table.getSelectedRow()
        if row < 0:
            return
        
        with self.domains_lock:
            for i in range(self.domains.size()):
                self.domains.get(i)["is_primary"] = (i == row)
        
        self._domain_model.fireTableDataChanged()
    
    def _clear_selected_session(self):
        """Clear session for selected domain"""
        row = self._domain_table.getSelectedRow()
        if row < 0:
            return
        
        with self.domains_lock:
            if row < self.domains.size():
                entry = self.domains.get(row)
                entry["session"] = {
                    "cookies": {},
                    "bearer": "",
                    "refresh_token": "",
                    "token_expiry": None,
                    "last_updated": None,
                    "status": "waiting"
                }
                self._log("Cleared session: " + entry["domain"])
        
        self._domain_model.fireTableDataChanged()
        self._update_session_detail()
    
    def _on_domain_selected(self):
        """Handle domain selection"""
        self._update_session_detail()
    
    def _update_session_detail(self):
        """Update session detail view"""
        row = self._domain_table.getSelectedRow()
        if row < 0:
            self._session_detail.setText("Select a domain to view details")
            return
        
        with self.domains_lock:
            if row >= self.domains.size():
                return
            
            entry = self.domains.get(row)
            domain = entry["domain"]
            session = entry["session"]
            auth_mode = entry["auth_mode"]
            
            text = "=" * 55 + "\n"
            text += "DOMAIN: " + domain + "\n"
            text += "=" * 55 + "\n\n"
            
            text += "CONFIGURATION:\n"
            text += "  Role: " + ("PRIMARY" if entry["is_primary"] else "Mirror") + "\n"
            text += "  Auth Mode: " + auth_mode + "\n"
            
            if auth_mode == AUTH_CUSTOM:
                text += "  Custom Header: " + entry.get("custom_header_name", "") + "\n"
                val = entry.get("custom_header_value", "")
                text += "  Custom Value: " + (val[:30] + "..." if len(val) > 30 else val) + "\n"
            
            text += "  Status: " + session["status"].upper() + "\n"
            text += "\n"
            
            text += "CAPTURED SESSION DATA:\n"
            text += "-" * 55 + "\n"
            
            # Bearer
            bearer = session.get("bearer", "")
            if bearer:
                text += "Access Token:\n  " + bearer[:70] + ("..." if len(bearer) > 70 else "") + "\n\n"
            else:
                text += "Access Token: (not captured)\n\n"
            
            # Refresh token
            refresh = session.get("refresh_token", "")
            if refresh:
                text += "Refresh Token:\n  " + refresh[:70] + ("..." if len(refresh) > 70 else "") + "\n\n"
            
            # Expiry
            expiry = session.get("token_expiry")
            if expiry:
                exp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(expiry))
                remaining = int(expiry - time.time())
                status = " (" + str(remaining) + "s remaining)" if remaining > 0 else " (EXPIRED)"
                text += "Token Expiry: " + exp_str + status + "\n\n"
            
            # Cookies
            cookies = session.get("cookies", {})
            if cookies:
                text += "Cookies (" + str(len(cookies)) + "):\n"
                for name, value in cookies.items():
                    disp = value[:40] + "..." if len(value) > 40 else value
                    text += "  " + name + " = " + disp + "\n"
            else:
                text += "Cookies: (none)\n"
            
            # Last updated
            last = session.get("last_updated")
            if last:
                text += "\nLast Updated: " + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last))
        
        self._session_detail.setText(text)
    
    def _toggle_mirroring(self):
        """Toggle mirroring"""
        self.mirror_enabled = self._mirror_checkbox.isSelected()
        self._log("=" * 40)
        self._log("Mirroring " + ("ENABLED" if self.mirror_enabled else "DISABLED"))
        
        # Debug: Print domains to console
        self._debug_print("Toggle mirroring. domains.size() = " + str(self.domains.size()))
        with self.domains_lock:
            for i in range(self.domains.size()):
                e = self.domains.get(i)
                self._debug_print("  [" + str(i) + "] " + e["domain"] + " (primary=" + str(e["is_primary"]) + ")")
        
        if self.mirror_enabled:
            # Show diagnostic info
            primary = self._get_primary_domain()
            mirrors = self._get_mirror_domains()
            
            if primary:
                self._log("PRIMARY: " + primary["domain"] + " (status: " + primary["session"]["status"] + ")")
            else:
                self._log("WARNING: No primary domain set!")
            
            if mirrors:
                for m in mirrors:
                    self._log("MIRROR: " + m["domain"] + " (status: " + m["session"]["status"] + ")")
            else:
                self._log("WARNING: No mirror domains configured!")
            
            # Show enabled tools
            enabled_tools = []
            if self.mirror_from_proxy: enabled_tools.append("Proxy")
            if self.mirror_from_repeater: enabled_tools.append("Repeater")
            if self.mirror_from_scanner: enabled_tools.append("Scanner")
            if self.mirror_from_intruder: enabled_tools.append("Intruder")
            if self.mirror_from_extender: enabled_tools.append("Extensions")
            
            self._log("TOOLS: " + (", ".join(enabled_tools) if enabled_tools else "NONE (check Settings!)"))
            if not self.mirror_from_proxy and not enabled_tools:
                self._log("WARNING: No tools enabled! Go to Settings to enable tool mirroring.")
        
        self._log("=" * 40)
    
    def _clear_results(self):
        """Clear results"""
        with self.results_lock:
            self.results.clear()
        self._results_model.fireTableDataChanged()
        if hasattr(self, '_results_count_label'):
            self._update_results_count()
        self._log("Results cleared")
    
    def _refresh_all_sessions(self):
        """Refresh all sessions"""
        with self.domains_lock:
            for i in range(self.domains.size()):
                domain = self.domains.get(i)["domain"]
                self._trigger_refresh(domain)
    
    def _build_results_panel(self):
        """Build results panel with enhanced diff viewing"""
        panel = JPanel(BorderLayout(5, 5))
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        
        # Table
        self._results_model = ResultsTableModel(self)
        self._results_table = JTable(self._results_model)
        self._results_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._results_table.getSelectionModel().addListSelectionListener(lambda e: self._on_result_selected())
        
        # Enable sorting on the table
        self._results_sorter = TableRowSorter(self._results_model)
        self._results_table.setRowSorter(self._results_sorter)
        
        # Set up custom comparators for proper sorting
        # Column 0: # (numeric)
        self._results_sorter.setComparator(0, NumericComparator())
        # Column 3: Match (YES/NO)
        self._results_sorter.setComparator(3, MatchComparator())
        # Column 4: Domains (numeric extraction)
        self._results_sorter.setComparator(4, DomainsComparator())
        
        self._results_table.getColumnModel().getColumn(3).setCellRenderer(MatchCellRenderer())
        
        self._results_table.getColumnModel().getColumn(0).setPreferredWidth(50)
        self._results_table.getColumnModel().getColumn(1).setPreferredWidth(60)
        self._results_table.getColumnModel().getColumn(2).setPreferredWidth(250)
        self._results_table.getColumnModel().getColumn(3).setPreferredWidth(60)
        self._results_table.getColumnModel().getColumn(4).setPreferredWidth(150)
        self._results_table.getColumnModel().getColumn(5).setPreferredWidth(80)
        
        # Detail panel with tabs for different views
        detail_panel = JPanel(BorderLayout())
        detail_panel.setBorder(BorderFactory.createTitledBorder("Response Comparison"))
        
        # Create tabbed pane for different comparison views
        self._comparison_tabs = JTabbedPane()
        
        # Summary view (original)
        self._response_area = JTextArea(12, 60)
        self._response_area.setEditable(False)
        self._response_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._comparison_tabs.addTab("Summary", JScrollPane(self._response_area))
        
        # Diff view - shows unified diff
        self._diff_area = JTextPane()
        self._diff_area.setEditable(False)
        self._diff_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._comparison_tabs.addTab("Diff View", JScrollPane(self._diff_area))
        
        # Full responses panel - side by side comparison
        self._full_response_panel = JPanel(BorderLayout())
        self._response_selector = JComboBox(["Select domain..."])
        self._response_selector.addActionListener(lambda e: self._show_selected_response())
        
        selector_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        selector_panel.add(JLabel("Domain:"))
        selector_panel.add(self._response_selector)
        
        self._full_body_area = JTextArea(12, 60)
        self._full_body_area.setEditable(False)
        self._full_body_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        
        self._full_response_panel.add(selector_panel, BorderLayout.NORTH)
        self._full_response_panel.add(JScrollPane(self._full_body_area), BorderLayout.CENTER)
        self._comparison_tabs.addTab("Full Response", self._full_response_panel)
        
        # Side-by-side view
        self._side_by_side_panel = self._build_side_by_side_panel()
        self._comparison_tabs.addTab("Side-by-Side", self._side_by_side_panel)
        
        detail_panel.add(self._comparison_tabs)
        
        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(self._results_table), detail_panel)
        split.setResizeWeight(0.4)
        
        panel.add(split, BorderLayout.CENTER)
        
        # === TOP CONTROL PANEL ===
        top_panel = JPanel(BorderLayout())
        
        # Filter and display options (row 1)
        filter_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        filter_panel.add(JLabel("Filter:"))
        self._filter_combo = JComboBox(["All", "Mismatches Only", "Matches Only"])
        self._filter_combo.addActionListener(lambda e: self._apply_filter_and_refresh())
        filter_panel.add(self._filter_combo)
        
        # Body length limit
        filter_panel.add(JLabel("   Max body display:"))
        self._body_limit_combo = JComboBox(["500 chars", "2000 chars", "5000 chars", "Full (no limit)"])
        self._body_limit_combo.setSelectedIndex(3)  # Default to full
        self._body_limit_combo.addActionListener(lambda e: self._on_result_selected())
        filter_panel.add(self._body_limit_combo)
        
        # Sort options
        filter_panel.add(JLabel("   Sort by:"))
        self._sort_combo = JComboBox(["# (Newest First)", "# (Oldest First)", "Method", "Path", "Match (Mismatches First)", "Match (Matches First)", "Time"])
        self._sort_combo.addActionListener(lambda e: self._apply_sort())
        filter_panel.add(self._sort_combo)
        
        top_panel.add(filter_panel, BorderLayout.NORTH)
        
        # Import/Export buttons (row 2)
        io_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        export_btn = JButton("Export CSV")
        export_btn.addActionListener(lambda e: self._export_results())
        io_panel.add(export_btn)
        
        export_diff_btn = JButton("Export Diff Report")
        export_diff_btn.addActionListener(lambda e: self._export_diff_report())
        io_panel.add(export_diff_btn)
        
        io_panel.add(JLabel("  |  "))
        
        save_session_btn = JButton("Save Session")
        save_session_btn.setToolTipText("Save all results to a JSON file for later import")
        save_session_btn.addActionListener(lambda e: self._save_session())
        io_panel.add(save_session_btn)
        
        load_session_btn = JButton("Load Session")
        load_session_btn.setToolTipText("Load results from a previously saved session")
        load_session_btn.addActionListener(lambda e: self._load_session())
        io_panel.add(load_session_btn)
        
        io_panel.add(JLabel("  |  "))
        
        clear_btn = JButton("Clear All")
        clear_btn.addActionListener(lambda e: self._clear_results_with_confirm())
        io_panel.add(clear_btn)
        
        # Results count label
        self._results_count_label = JLabel("  Results: 0")
        io_panel.add(self._results_count_label)
        
        top_panel.add(io_panel, BorderLayout.SOUTH)
        
        panel.add(top_panel, BorderLayout.NORTH)
        
        # Store current result for reference
        self._current_result = None
        
        return panel
    
    def _apply_filter_and_refresh(self):
        """Apply filter and refresh the table"""
        self._results_model.fireTableDataChanged()
        self._update_results_count()
    
    def _apply_sort(self):
        """Apply sorting based on selected option"""
        sort_option = self._sort_combo.getSelectedItem()
        
        sort_keys = []
        
        if "# (Newest First)" in sort_option:
            sort_keys.append(RowSorter.SortKey(0, SortOrder.DESCENDING))
        elif "# (Oldest First)" in sort_option:
            sort_keys.append(RowSorter.SortKey(0, SortOrder.ASCENDING))
        elif "Method" in sort_option:
            sort_keys.append(RowSorter.SortKey(1, SortOrder.ASCENDING))
        elif "Path" in sort_option:
            sort_keys.append(RowSorter.SortKey(2, SortOrder.ASCENDING))
        elif "Mismatches First" in sort_option:
            sort_keys.append(RowSorter.SortKey(3, SortOrder.ASCENDING))  # NO comes before YES
        elif "Matches First" in sort_option:
            sort_keys.append(RowSorter.SortKey(3, SortOrder.DESCENDING))  # YES comes before NO
        elif "Time" in sort_option:
            sort_keys.append(RowSorter.SortKey(5, SortOrder.DESCENDING))
        
        self._results_sorter.setSortKeys(sort_keys)
    
    def _update_results_count(self):
        """Update the results count label"""
        total = self.results.size()
        mismatches = sum(1 for i in range(total) if not self.results.get(i).get("match"))
        matches = total - mismatches
        
        filter_val = self._filter_combo.getSelectedItem() if hasattr(self, '_filter_combo') else "All"
        
        if filter_val == "All":
            shown = total
        elif filter_val == "Mismatches Only":
            shown = mismatches
        else:
            shown = matches
        
        self._results_count_label.setText("  Results: {} shown ({} total, {} mismatches)".format(shown, total, mismatches))
    
    def _clear_results_with_confirm(self):
        """Clear results with confirmation"""
        if self.results.size() == 0:
            return
        
        result = JOptionPane.showConfirmDialog(
            self._main_panel,
            "Are you sure you want to clear all {} results?".format(self.results.size()),
            "Confirm Clear",
            JOptionPane.YES_NO_OPTION
        )
        
        if result == JOptionPane.YES_OPTION:
            self._clear_results()
    
    def _save_session(self):
        """Save all results to a JSON file"""
        try:
            chooser = JFileChooser()
            chooser.setDialogTitle("Save Session Results")
            chooser.setSelectedFile(java.io.File("domain_mirror_session_" + time.strftime("%Y%m%d_%H%M%S") + ".json"))
            chooser.setFileFilter(FileNameExtensionFilter("JSON Files", ["json"]))
            
            if chooser.showSaveDialog(self._main_panel) != JFileChooser.APPROVE_OPTION:
                return
            
            filepath = chooser.getSelectedFile().getAbsolutePath()
            if not filepath.endswith(".json"):
                filepath += ".json"
            
            # Convert results to serializable format
            session_data = {
                "version": "5.0",
                "exported": time.strftime("%Y-%m-%d %H:%M:%S"),
                "results": []
            }
            
            for i in range(self.results.size()):
                r = self.results.get(i)
                session_data["results"].append({
                    "method": r.get("method", ""),
                    "path": r.get("path", ""),
                    "timestamp": r.get("timestamp", ""),
                    "match": r.get("match", True),
                    "responses": r.get("responses", {})
                })
            
            with open(filepath, "w") as f:
                json.dump(session_data, f, indent=2)
            
            self._log("Session saved to " + filepath + " (" + str(self.results.size()) + " results)")
            JOptionPane.showMessageDialog(
                self._main_panel,
                "Saved {} results to:\n{}".format(self.results.size(), filepath)
            )
        
        except Exception as e:
            self._log("Save session error: " + str(e))
            JOptionPane.showMessageDialog(self._main_panel, "Error saving session: " + str(e))
    
    def _load_session(self):
        """Load results from a JSON file"""
        try:
            chooser = JFileChooser()
            chooser.setDialogTitle("Load Session Results")
            chooser.setFileFilter(FileNameExtensionFilter("JSON Files", ["json"]))
            
            if chooser.showOpenDialog(self._main_panel) != JFileChooser.APPROVE_OPTION:
                return
            
            filepath = chooser.getSelectedFile().getAbsolutePath()
            
            with open(filepath, "r") as f:
                session_data = json.load(f)
            
            # Validate format
            if "results" not in session_data:
                raise ValueError("Invalid session file format")
            
            # Ask about merge vs replace
            if self.results.size() > 0:
                choice = JOptionPane.showOptionDialog(
                    self._main_panel,
                    "You have {} existing results. What would you like to do?".format(self.results.size()),
                    "Load Session",
                    JOptionPane.YES_NO_CANCEL_OPTION,
                    JOptionPane.QUESTION_MESSAGE,
                    None,
                    ["Merge (Add to existing)", "Replace (Clear existing)", "Cancel"],
                    "Merge (Add to existing)"
                )
                
                if choice == 2 or choice == JOptionPane.CLOSED_OPTION:  # Cancel
                    return
                elif choice == 1:  # Replace
                    with self.results_lock:
                        self.results.clear()
            
            # Load results
            loaded_count = 0
            with self.results_lock:
                for r in session_data["results"]:
                    # Respect max results limit
                    if self.results.size() >= self._max_results:
                        self._log("WARNING: Max results limit reached during import (" + str(self._max_results) + ")")
                        break
                    self.results.add({
                        "method": r.get("method", ""),
                        "path": r.get("path", ""),
                        "timestamp": r.get("timestamp", ""),
                        "match": r.get("match", True),
                        "responses": r.get("responses", {})
                    })
                    loaded_count += 1
            
            self._results_model.fireTableDataChanged()
            self._update_results_count()
            
            version = session_data.get("version", "unknown")
            exported = session_data.get("exported", "unknown")
            
            self._log("Loaded {} results from {} (v{}, exported {})".format(loaded_count, filepath, version, exported))
            JOptionPane.showMessageDialog(
                self._main_panel,
                "Loaded {} results from:\n{}\n\nExported: {}".format(loaded_count, filepath, exported)
            )
        
        except Exception as e:
            self._log("Load session error: " + str(e))
            JOptionPane.showMessageDialog(self._main_panel, "Error loading session: " + str(e))
    
    def _build_side_by_side_panel(self):
        """Build side-by-side comparison panel with synchronized scrolling"""
        panel = JPanel(BorderLayout())
        
        # Selector for domains + sync scroll option
        selector_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        selector_panel.add(JLabel("Left:"))
        self._left_domain_combo = JComboBox(["Select..."])
        self._left_domain_combo.addActionListener(lambda e: self._trigger_side_by_side_update())
        selector_panel.add(self._left_domain_combo)
        
        selector_panel.add(JLabel("   Right:"))
        self._right_domain_combo = JComboBox(["Select..."])
        self._right_domain_combo.addActionListener(lambda e: self._trigger_side_by_side_update())
        selector_panel.add(self._right_domain_combo)
        
        # Add sync scroll checkbox
        selector_panel.add(JLabel("     "))
        self._sync_scroll_checkbox = JCheckBox("Lock Scroll", True)
        self._sync_scroll_checkbox.setToolTipText("Synchronize scrolling between left and right panels")
        selector_panel.add(self._sync_scroll_checkbox)
        
        panel.add(selector_panel, BorderLayout.NORTH)
        
        # Two text areas side by side
        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        
        left_panel = JPanel(BorderLayout())
        left_panel.setBorder(BorderFactory.createTitledBorder("Left Response"))
        self._left_response_area = JTextPane()
        self._left_response_area.setEditable(False)
        self._left_response_area.setFont(Font("Monospaced", Font.PLAIN, 10))
        self._left_scroll_pane = JScrollPane(self._left_response_area)
        left_panel.add(self._left_scroll_pane)
        
        right_panel = JPanel(BorderLayout())
        right_panel.setBorder(BorderFactory.createTitledBorder("Right Response"))
        self._right_response_area = JTextPane()
        self._right_response_area.setEditable(False)
        self._right_response_area.setFont(Font("Monospaced", Font.PLAIN, 10))
        self._right_scroll_pane = JScrollPane(self._right_response_area)
        right_panel.add(self._right_scroll_pane)
        
        # Set up synchronized scrolling
        self._scroll_sync_active = False  # Flag to prevent recursive updates
        
        # Get the vertical scrollbars
        left_vbar = self._left_scroll_pane.getVerticalScrollBar()
        right_vbar = self._right_scroll_pane.getVerticalScrollBar()
        left_hbar = self._left_scroll_pane.getHorizontalScrollBar()
        right_hbar = self._right_scroll_pane.getHorizontalScrollBar()
        
        # Create adjustment listeners for synchronized scrolling
        def sync_left_to_right_v(e):
            if self._scroll_sync_active:
                return
            if self._sync_scroll_checkbox.isSelected():
                self._scroll_sync_active = True
                try:
                    # Calculate relative position
                    left_max = left_vbar.getMaximum() - left_vbar.getVisibleAmount()
                    right_max = right_vbar.getMaximum() - right_vbar.getVisibleAmount()
                    if left_max > 0 and right_max > 0:
                        ratio = float(left_vbar.getValue()) / float(left_max)
                        right_vbar.setValue(int(ratio * right_max))
                    elif left_max <= 0:
                        right_vbar.setValue(0)
                finally:
                    self._scroll_sync_active = False
        
        def sync_right_to_left_v(e):
            if self._scroll_sync_active:
                return
            if self._sync_scroll_checkbox.isSelected():
                self._scroll_sync_active = True
                try:
                    left_max = left_vbar.getMaximum() - left_vbar.getVisibleAmount()
                    right_max = right_vbar.getMaximum() - right_vbar.getVisibleAmount()
                    if right_max > 0 and left_max > 0:
                        ratio = float(right_vbar.getValue()) / float(right_max)
                        left_vbar.setValue(int(ratio * left_max))
                    elif right_max <= 0:
                        left_vbar.setValue(0)
                finally:
                    self._scroll_sync_active = False
        
        def sync_left_to_right_h(e):
            if self._scroll_sync_active:
                return
            if self._sync_scroll_checkbox.isSelected():
                self._scroll_sync_active = True
                try:
                    left_max = left_hbar.getMaximum() - left_hbar.getVisibleAmount()
                    right_max = right_hbar.getMaximum() - right_hbar.getVisibleAmount()
                    if left_max > 0 and right_max > 0:
                        ratio = float(left_hbar.getValue()) / float(left_max)
                        right_hbar.setValue(int(ratio * right_max))
                    elif left_max <= 0:
                        right_hbar.setValue(0)
                finally:
                    self._scroll_sync_active = False
        
        def sync_right_to_left_h(e):
            if self._scroll_sync_active:
                return
            if self._sync_scroll_checkbox.isSelected():
                self._scroll_sync_active = True
                try:
                    left_max = left_hbar.getMaximum() - left_hbar.getVisibleAmount()
                    right_max = right_hbar.getMaximum() - right_hbar.getVisibleAmount()
                    if right_max > 0 and left_max > 0:
                        ratio = float(right_hbar.getValue()) / float(right_max)
                        left_hbar.setValue(int(ratio * left_max))
                    elif right_max <= 0:
                        left_hbar.setValue(0)
                finally:
                    self._scroll_sync_active = False
        
        # Add the listeners
        from java.awt.event import AdjustmentListener
        
        class LeftVScrollListener(AdjustmentListener):
            def __init__(self, callback):
                self.callback = callback
            def adjustmentValueChanged(self, e):
                self.callback(e)
        
        class RightVScrollListener(AdjustmentListener):
            def __init__(self, callback):
                self.callback = callback
            def adjustmentValueChanged(self, e):
                self.callback(e)
        
        class LeftHScrollListener(AdjustmentListener):
            def __init__(self, callback):
                self.callback = callback
            def adjustmentValueChanged(self, e):
                self.callback(e)
        
        class RightHScrollListener(AdjustmentListener):
            def __init__(self, callback):
                self.callback = callback
            def adjustmentValueChanged(self, e):
                self.callback(e)
        
        left_vbar.addAdjustmentListener(LeftVScrollListener(sync_left_to_right_v))
        right_vbar.addAdjustmentListener(RightVScrollListener(sync_right_to_left_v))
        left_hbar.addAdjustmentListener(LeftHScrollListener(sync_left_to_right_h))
        right_hbar.addAdjustmentListener(RightHScrollListener(sync_right_to_left_h))
        
        split.setLeftComponent(left_panel)
        split.setRightComponent(right_panel)
        split.setResizeWeight(0.5)
        
        panel.add(split, BorderLayout.CENTER)
        
        return panel
    
    def _get_body_limit(self):
        """Get current body display limit"""
        if not hasattr(self, '_body_limit_combo'):
            return None
        selected = self._body_limit_combo.getSelectedItem()
        if "500" in selected:
            return 500
        elif "2000" in selected:
            return 2000
        elif "5000" in selected:
            return 5000
        else:
            return None  # No limit
    
    def _on_result_selected(self):
        """Handle result selection - populate all comparison views"""
        view_row = self._results_table.getSelectedRow()
        if view_row < 0:
            return
        
        # Convert view row to model row (important when table is sorted!)
        model_row = view_row
        if hasattr(self, '_results_sorter') and self._results_sorter:
            try:
                model_row = self._results_table.convertRowIndexToModel(view_row)
            except:
                pass  # Fall back to view_row if conversion fails
        
        # Get actual index after filtering
        filter_val = self._filter_combo.getSelectedItem()
        actual_idx = self._get_filtered_result_index(model_row, filter_val)
        
        if actual_idx < 0 or actual_idx >= self.results.size():
            return
        
        result = self.results.get(actual_idx)
        self._current_result = result
        
        responses = result.get("responses", {})
        domains = list(responses.keys())
        body_limit = self._get_body_limit()
        
        # Update domain selectors
        self._response_selector.removeAllItems()
        self._left_domain_combo.removeAllItems()
        self._right_domain_combo.removeAllItems()
        
        for domain in domains:
            self._response_selector.addItem(domain)
            self._left_domain_combo.addItem(domain)
            self._right_domain_combo.addItem(domain)
        
        if len(domains) >= 2:
            self._left_domain_combo.setSelectedIndex(0)
            self._right_domain_combo.setSelectedIndex(1)
        
        # === SUMMARY TAB (fast, do immediately) ===
        text = "REQUEST: " + result.get("method", "") + " " + result.get("path", "") + "\n"
        text += "TIME: " + result.get("timestamp", "") + "\n"
        text += "MATCH: " + ("YES - All responses identical" if result.get("match") else "NO - Differences detected!") + "\n"
        text += "=" * 70 + "\n\n"
        
        # Summary table
        text += "RESPONSE SUMMARY:\n"
        text += "-" * 70 + "\n"
        text += "{:<30} {:>8} {:>10} {:>15}\n".format("Domain", "Status", "Size", "Hash")
        text += "-" * 70 + "\n"
        
        for domain, data in responses.items():
            text += "{:<30} {:>8} {:>10} {:>15}\n".format(
                domain[:30],
                str(data.get("status", "?")),
                str(data.get("size", 0)),
                data.get("hash", "")[:15]
            )
        
        # Show truncated bodies if mismatch
        if not result.get("match"):
            text += "\n" + "=" * 70 + "\n"
            text += "RESPONSE PREVIEWS:\n"
            text += "(See 'Diff View' tab for detailed comparison)\n"
            text += "=" * 70 + "\n"
            
            for domain, data in responses.items():
                text += "\n--- " + domain + " [" + str(data.get("status", "?")) + "] ---\n"
                body = data.get("body", "")
                if body_limit and len(body) > body_limit:
                    text += body[:body_limit] + "\n... [truncated, " + str(len(body)) + " total chars]\n"
                else:
                    text += body + "\n"
        
        self._response_area.setText(text)
        
        # === DIFF TAB (heavy - do in background) ===
        # Show loading indicator immediately
        self._diff_area.setText("Loading diff... (large responses may take a moment)")
        
        # Process in background thread
        def compute_diff():
            self._update_diff_view(result, responses, domains)
        
        t = Thread(target=compute_diff)
        t.daemon = True
        t.start()
        
        # === SIDE BY SIDE (heavy - do in background) ===
        # Show loading indicator immediately
        self._left_response_area.setText("Loading...")
        self._right_response_area.setText("Loading...")
        
        def compute_side_by_side():
            self._update_side_by_side()
        
        t2 = Thread(target=compute_side_by_side)
        t2.daemon = True
        t2.start()
    
    def _update_diff_view(self, result, responses, domains):
        """Update the diff view with highlighted differences - runs in background thread"""
        try:
            # Pre-compute all the diff content in background thread
            diff_content = []  # List of (text, style_name) tuples
            
            if result.get("match"):
                diff_content.append(("All responses are IDENTICAL\n\n", "header"))
                diff_content.append(("Hash: " + list(responses.values())[0].get("hash", ""), "normal"))
            else:
                diff_content.append(("DIFFERENCES DETECTED\n", "header"))
                diff_content.append(("=" * 70 + "\n\n", "separator"))
                
                # Compare each pair of responses
                if len(domains) >= 2:
                    primary_domain = domains[0]
                    primary_data = responses[primary_domain]
                    primary_body = primary_data.get("body", "")
                    
                    # Limit body size for diff calculation to prevent massive memory usage
                    max_diff_body_size = 100000  # 100KB limit for diff calculation
                    if len(primary_body) > max_diff_body_size:
                        primary_body = primary_body[:max_diff_body_size]
                        diff_content.append(("WARNING: Primary body truncated to {}KB for diff\n\n".format(max_diff_body_size // 1000), "separator"))
                    
                    for other_domain in domains[1:]:
                        other_data = responses[other_domain]
                        other_body = other_data.get("body", "")
                        
                        if len(other_body) > max_diff_body_size:
                            other_body = other_body[:max_diff_body_size]
                        
                        diff_content.append(("Comparing: {} vs {}\n".format(primary_domain, other_domain), "header"))
                        diff_content.append(("-" * 70 + "\n", "separator"))
                        
                        # Status comparison
                        if primary_data.get("status") != other_data.get("status"):
                            diff_content.append(("Status: ", "normal"))
                            diff_content.append((str(primary_data.get("status")), "removed"))
                            diff_content.append((" vs ", "normal"))
                            diff_content.append((str(other_data.get("status")), "added"))
                            diff_content.append(("\n", "normal"))
                        
                        # Size comparison
                        if primary_data.get("size") != other_data.get("size"):
                            diff_content.append(("Size: ", "normal"))
                            diff_content.append((str(primary_data.get("size")), "removed"))
                            diff_content.append((" vs ", "normal"))
                            diff_content.append((str(other_data.get("size")), "added"))
                            diff_content.append(("\n", "normal"))
                        
                        diff_content.append(("\n", "normal"))
                        
                        # Generate unified diff
                        primary_lines = primary_body.splitlines(keepends=True)
                        other_lines = other_body.splitlines(keepends=True)
                        
                        diff = list(difflib.unified_diff(
                            primary_lines, 
                            other_lines,
                            fromfile=primary_domain,
                            tofile=other_domain,
                            lineterm=''
                        ))
                        
                        if diff:
                            diff_content.append(("UNIFIED DIFF:\n", "header"))
                            
                            diff_line_count = 0
                            
                            for line in diff:
                                if diff_line_count >= self._max_diff_lines:
                                    diff_content.append((
                                        "\n... [diff truncated, showing first {} lines]\n".format(self._max_diff_lines), 
                                        "separator"
                                    ))
                                    break
                                
                                if line.startswith('+++') or line.startswith('---'):
                                    diff_content.append((line + "\n", "header"))
                                elif line.startswith('@@'):
                                    diff_content.append((line + "\n", "separator"))
                                elif line.startswith('+'):
                                    diff_content.append((line + "\n", "added"))
                                elif line.startswith('-'):
                                    diff_content.append((line + "\n", "removed"))
                                else:
                                    diff_content.append((line + "\n", "normal"))
                                
                                diff_line_count += 1
                        else:
                            diff_content.append(("Body content is identical (difference may be in headers)\n", "normal"))
                        
                        diff_content.append(("\n" + "=" * 70 + "\n\n", "separator"))
            
            # Now update UI on EDT
            def update_ui():
                try:
                    doc = self._diff_area.getStyledDocument()
                    doc.remove(0, doc.getLength())
                    
                    # Define styles
                    style_context = StyleContext.getDefaultStyleContext()
                    
                    styles = {}
                    styles["normal"] = style_context.addStyle("normal", None)
                    StyleConstants.setFontFamily(styles["normal"], "Monospaced")
                    StyleConstants.setFontSize(styles["normal"], 11)
                    
                    styles["header"] = style_context.addStyle("header", None)
                    StyleConstants.setFontFamily(styles["header"], "Monospaced")
                    StyleConstants.setFontSize(styles["header"], 11)
                    StyleConstants.setBold(styles["header"], True)
                    StyleConstants.setForeground(styles["header"], Color(0, 0, 150))
                    
                    styles["added"] = style_context.addStyle("added", None)
                    StyleConstants.setFontFamily(styles["added"], "Monospaced")
                    StyleConstants.setFontSize(styles["added"], 11)
                    StyleConstants.setBackground(styles["added"], Color(200, 255, 200))
                    StyleConstants.setForeground(styles["added"], Color(0, 100, 0))
                    
                    styles["removed"] = style_context.addStyle("removed", None)
                    StyleConstants.setFontFamily(styles["removed"], "Monospaced")
                    StyleConstants.setFontSize(styles["removed"], 11)
                    StyleConstants.setBackground(styles["removed"], Color(255, 200, 200))
                    StyleConstants.setForeground(styles["removed"], Color(150, 0, 0))
                    
                    styles["separator"] = style_context.addStyle("separator", None)
                    StyleConstants.setFontFamily(styles["separator"], "Monospaced")
                    StyleConstants.setFontSize(styles["separator"], 11)
                    StyleConstants.setForeground(styles["separator"], Color(100, 100, 100))
                    
                    # Apply pre-computed content
                    for text, style_name in diff_content:
                        doc.insertString(doc.getLength(), text, styles.get(style_name, styles["normal"]))
                except Exception as e:
                    self._debug_print("Error updating diff UI: " + str(e))
            
            SwingUtilities.invokeLater(update_ui)
            
        except Exception as e:
            def show_error():
                self._diff_area.setText("Error computing diff: " + str(e))
            SwingUtilities.invokeLater(show_error)
    
    def _show_selected_response(self):
        """Show the full response for selected domain"""
        if not self._current_result:
            return
        
        selected = self._response_selector.getSelectedItem()
        if not selected or selected == "Select domain...":
            return
        
        responses = self._current_result.get("responses", {})
        if selected in responses:
            data = responses[selected]
            body = data.get("body", "")
            
            text = "Domain: " + selected + "\n"
            text += "Status: " + str(data.get("status", "?")) + "\n"
            text += "Size: " + str(data.get("size", 0)) + " bytes\n"
            text += "Hash: " + data.get("hash", "") + "\n"
            text += "=" * 60 + "\n\n"
            text += body
            
            self._full_body_area.setText(text)
            self._full_body_area.setCaretPosition(0)
    
    def _trigger_side_by_side_update(self):
        """Trigger side-by-side update with loading indicator"""
        # Show loading immediately
        self._left_response_area.setText("Loading...")
        self._right_response_area.setText("Loading...")
        
        # Run update in background
        def do_update():
            self._update_side_by_side()
        
        t = Thread(target=do_update)
        t.daemon = True
        t.start()
    
    def _update_side_by_side(self):
        """Update side-by-side comparison view with highlighting - runs in background thread"""
        try:
            if not self._current_result:
                return
            
            # Get values on current thread (may or may not be EDT)
            left_domain = self._left_domain_combo.getSelectedItem()
            right_domain = self._right_domain_combo.getSelectedItem()
            
            if not left_domain or not right_domain:
                return
            
            responses = self._current_result.get("responses", {})
            
            left_data = responses.get(left_domain, {})
            right_data = responses.get(right_domain, {})
            
            left_body = left_data.get("body", "")
            right_body = right_data.get("body", "")
            
            # Limit body size for comparison to prevent freezing
            max_side_by_side_size = 50000  # 50KB limit for side-by-side
            left_truncated = False
            right_truncated = False
            
            if len(left_body) > max_side_by_side_size:
                left_body = left_body[:max_side_by_side_size]
                left_truncated = True
            if len(right_body) > max_side_by_side_size:
                right_body = right_body[:max_side_by_side_size]
                right_truncated = True
            
            # Build headers
            left_header = "Status: {} | Size: {} | Hash: {}\n{}\n".format(
                left_data.get("status", "?"),
                left_data.get("size", 0),
                left_data.get("hash", "")[:12],
                "=" * 40
            )
            if left_truncated:
                left_header += "(truncated to 50KB for display)\n"
            left_header += "\n"
            
            right_header = "Status: {} | Size: {} | Hash: {}\n{}\n".format(
                right_data.get("status", "?"),
                right_data.get("size", 0),
                right_data.get("hash", "")[:12],
                "=" * 40
            )
            if right_truncated:
                right_header += "(truncated to 50KB for display)\n"
            right_header += "\n"
            
            # Pre-compute the comparison in background
            left_content = []  # (text, is_diff) tuples
            right_content = []
            
            left_content.append((left_header, False))
            right_content.append((right_header, False))
            
            # Split into lines and compare
            left_lines = left_body.splitlines()
            right_lines = right_body.splitlines()
            
            # Use SequenceMatcher to find differences
            matcher = difflib.SequenceMatcher(None, left_lines, right_lines)
            
            for tag, i1, i2, j1, j2 in matcher.get_opcodes():
                if tag == 'equal':
                    for line in left_lines[i1:i2]:
                        left_content.append((line + "\n", False))
                    for line in right_lines[j1:j2]:
                        right_content.append((line + "\n", False))
                elif tag == 'replace':
                    for line in left_lines[i1:i2]:
                        left_content.append((line + "\n", True))
                    for line in right_lines[j1:j2]:
                        right_content.append((line + "\n", True))
                elif tag == 'delete':
                    for line in left_lines[i1:i2]:
                        left_content.append((line + "\n", True))
                elif tag == 'insert':
                    for line in right_lines[j1:j2]:
                        right_content.append((line + "\n", True))
            
            # Now update UI on EDT
            def update_ui():
                try:
                    left_doc = self._left_response_area.getStyledDocument()
                    right_doc = self._right_response_area.getStyledDocument()
                    
                    left_doc.remove(0, left_doc.getLength())
                    right_doc.remove(0, right_doc.getLength())
                    
                    # Define styles
                    style_context = StyleContext.getDefaultStyleContext()
                    
                    normal_style = style_context.addStyle("normal", None)
                    StyleConstants.setFontFamily(normal_style, "Monospaced")
                    StyleConstants.setFontSize(normal_style, 10)
                    
                    diff_style = style_context.addStyle("diff", None)
                    StyleConstants.setFontFamily(diff_style, "Monospaced")
                    StyleConstants.setFontSize(diff_style, 10)
                    StyleConstants.setBackground(diff_style, Color(255, 255, 150))
                    
                    header_style = style_context.addStyle("header", None)
                    StyleConstants.setFontFamily(header_style, "Monospaced")
                    StyleConstants.setFontSize(header_style, 10)
                    StyleConstants.setBold(header_style, True)
                    
                    # Apply left content
                    for i, (text, is_diff) in enumerate(left_content):
                        if i == 0:  # Header
                            left_doc.insertString(left_doc.getLength(), text, header_style)
                        else:
                            left_doc.insertString(left_doc.getLength(), text, diff_style if is_diff else normal_style)
                    
                    # Apply right content
                    for i, (text, is_diff) in enumerate(right_content):
                        if i == 0:  # Header
                            right_doc.insertString(right_doc.getLength(), text, header_style)
                        else:
                            right_doc.insertString(right_doc.getLength(), text, diff_style if is_diff else normal_style)
                    
                    # Move to top
                    self._left_response_area.setCaretPosition(0)
                    self._right_response_area.setCaretPosition(0)
                except Exception as e:
                    self._debug_print("Error updating side-by-side UI: " + str(e))
            
            SwingUtilities.invokeLater(update_ui)
            
        except Exception as e:
            def show_error():
                self._left_response_area.setText("Error: " + str(e))
                self._right_response_area.setText("Error: " + str(e))
            SwingUtilities.invokeLater(show_error)
    
    def _export_diff_report(self):
        """Export detailed diff report"""
        try:
            filename = "domain_mirror_diff_" + time.strftime("%Y%m%d_%H%M%S") + ".txt"
            
            with open(filename, "w") as f:
                f.write("Domain Mirror Diff Report\n")
                f.write("Generated: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
                f.write("=" * 80 + "\n\n")
                
                mismatch_count = 0
                
                for i in range(self.results.size()):
                    result = self.results.get(i)
                    if not result.get("match"):
                        mismatch_count += 1
                        f.write("\n" + "=" * 80 + "\n")
                        f.write("MISMATCH #{}\n".format(mismatch_count))
                        f.write("=" * 80 + "\n")
                        f.write("Request: {} {}\n".format(result.get("method", ""), result.get("path", "")))
                        f.write("Time: {}\n\n".format(result.get("timestamp", "")))
                        
                        responses = result.get("responses", {})
                        domains = list(responses.keys())
                        
                        # Summary
                        f.write("Response Summary:\n")
                        f.write("-" * 60 + "\n")
                        for domain, data in responses.items():
                            f.write("{}: status={}, size={}, hash={}\n".format(
                                domain, data.get("status"), data.get("size"), data.get("hash", "")[:16]
                            ))
                        
                        # Diff for each pair
                        if len(domains) >= 2:
                            primary = domains[0]
                            primary_body = responses[primary].get("body", "")
                            
                            for other in domains[1:]:
                                other_body = responses[other].get("body", "")
                                
                                f.write("\n\nDiff: {} vs {}\n".format(primary, other))
                                f.write("-" * 60 + "\n")
                                
                                diff = difflib.unified_diff(
                                    primary_body.splitlines(keepends=True),
                                    other_body.splitlines(keepends=True),
                                    fromfile=primary,
                                    tofile=other
                                )
                                f.writelines(diff)
                        
                        # Full bodies
                        f.write("\n\nFull Response Bodies:\n")
                        f.write("-" * 60 + "\n")
                        for domain, data in responses.items():
                            f.write("\n--- {} ---\n".format(domain))
                            f.write(data.get("body", "(empty)"))
                            f.write("\n")
                
                f.write("\n\n" + "=" * 80 + "\n")
                f.write("Total mismatches: {}\n".format(mismatch_count))
            
            self._log("Exported diff report to " + filename)
            JOptionPane.showMessageDialog(self._main_panel, 
                "Exported {} mismatches to {}".format(mismatch_count, filename))
        
        except Exception as e:
            self._log("Export error: " + str(e))
            JOptionPane.showMessageDialog(self._main_panel, "Export failed: " + str(e))
    
    def _get_filtered_result_index(self, filtered_row, filter_val):
        """Get actual result index from filtered row"""
        filtered_idx = 0
        for i in range(self.results.size()):
            r = self.results.get(i)
            include = (filter_val == "All" or 
                      (filter_val == "Mismatches Only" and not r.get("match")) or
                      (filter_val == "Matches Only" and r.get("match")))
            if include:
                if filtered_idx == filtered_row:
                    return i
                filtered_idx += 1
        return -1
    
    def _export_results(self):
        """Export results"""
        try:
            filename = "domain_mirror_" + time.strftime("%Y%m%d_%H%M%S") + ".csv"
            
            with open(filename, "w") as f:
                f.write("Index,Method,Path,Match,Timestamp,Domains,Hashes\n")
                
                for i in range(self.results.size()):
                    r = self.results.get(i)
                    responses = r.get("responses", {})
                    domains_str = ";".join(responses.keys())
                    hashes_str = ";".join([d.get("hash", "")[:8] for d in responses.values()])
                    
                    f.write("{},{},\"{}\",{},{},{},{}\n".format(
                        i + 1,
                        r.get("method", ""),
                        r.get("path", "").replace('"', '""'),
                        "Yes" if r.get("match") else "No",
                        r.get("timestamp", ""),
                        domains_str,
                        hashes_str
                    ))
            
            self._log("Exported to " + filename)
            JOptionPane.showMessageDialog(self._main_panel, "Exported to " + filename)
        except Exception as e:
            self._log("Export error: " + str(e))
    
    def _build_settings_panel(self):
        """Build settings panel"""
        panel = JPanel(BorderLayout(10, 10))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        settings = JPanel()
        settings.setLayout(BoxLayout(settings, BoxLayout.Y_AXIS))
        
        # === TOOL INTERCEPTION SECTION ===
        tools_panel = JPanel()
        tools_panel.setLayout(BoxLayout(tools_panel, BoxLayout.Y_AXIS))
        tools_panel.setBorder(BorderFactory.createTitledBorder("Mirror Requests From (Burp Tools)"))
        tools_panel.setMaximumSize(Dimension(800, 180))
        
        tools_help = JLabel("Select which Burp tools should trigger request mirroring:")
        tools_help.setAlignmentX(0.0)
        tools_panel.add(tools_help)
        tools_panel.add(JLabel(" "))
        
        # Checkboxes for each tool
        tools_row1 = JPanel(FlowLayout(FlowLayout.LEFT))
        
        self._proxy_checkbox = JCheckBox("Proxy (browser traffic)", True)
        self._proxy_checkbox.setToolTipText("Mirror requests captured through the Burp Proxy")
        tools_row1.add(self._proxy_checkbox)
        
        self._repeater_checkbox = JCheckBox("Repeater", False)
        self._repeater_checkbox.setToolTipText("Mirror requests sent from Repeater")
        tools_row1.add(self._repeater_checkbox)
        
        self._scanner_checkbox = JCheckBox("Scanner", False)
        self._scanner_checkbox.setToolTipText("Mirror requests from active/passive scanner")
        tools_row1.add(self._scanner_checkbox)
        
        tools_panel.add(tools_row1)
        
        tools_row2 = JPanel(FlowLayout(FlowLayout.LEFT))
        
        self._intruder_checkbox = JCheckBox("Intruder", False)
        self._intruder_checkbox.setToolTipText("Mirror requests from Intruder attacks")
        tools_row2.add(self._intruder_checkbox)
        
        self._extender_checkbox = JCheckBox("Extensions", False)
        self._extender_checkbox.setToolTipText("Mirror requests from other Burp extensions (safe - won't create infinite loops)")
        tools_row2.add(self._extender_checkbox)
        
        tools_panel.add(tools_row2)
        
        tools_note = JLabel("<html>Note: Scanner/Intruder may generate high volumes. Extensions is safe (no infinite loops).</html>")
        tools_note.setForeground(Color(150, 100, 0))
        tools_note.setAlignmentX(0.0)
        tools_panel.add(JLabel(" "))
        tools_panel.add(tools_note)
        
        settings.add(tools_panel)
        settings.add(JLabel(" "))
        
        # === LOGIN PATTERNS ===
        login_panel = JPanel(BorderLayout())
        login_panel.setBorder(BorderFactory.createTitledBorder("Login Detection Patterns (comma-separated)"))
        login_panel.setMaximumSize(Dimension(800, 100))
        
        self._login_patterns_field = JTextArea(2, 50)
        self._login_patterns_field.setText(", ".join(self.login_patterns))
        login_panel.add(JScrollPane(self._login_patterns_field))
        settings.add(login_panel)
        settings.add(JLabel(" "))
        
        # Refresh patterns
        refresh_panel = JPanel(BorderLayout())
        refresh_panel.setBorder(BorderFactory.createTitledBorder("Token Refresh Patterns"))
        refresh_panel.setMaximumSize(Dimension(800, 80))
        
        self._refresh_patterns_field = JTextArea(2, 50)
        self._refresh_patterns_field.setText(", ".join(self.refresh_patterns))
        refresh_panel.add(JScrollPane(self._refresh_patterns_field))
        settings.add(refresh_panel)
        settings.add(JLabel(" "))
        
        # Token keys
        token_panel = JPanel(BorderLayout())
        token_panel.setBorder(BorderFactory.createTitledBorder("Token JSON Keys"))
        token_panel.setMaximumSize(Dimension(800, 80))
        
        self._token_keys_field = JTextArea(2, 50)
        self._token_keys_field.setText(", ".join(self.token_keys))
        token_panel.add(JScrollPane(self._token_keys_field))
        settings.add(token_panel)
        settings.add(JLabel(" "))
        
        # Options
        options_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        options_panel.setBorder(BorderFactory.createTitledBorder("Options"))
        options_panel.setMaximumSize(Dimension(800, 60))
        
        self._auto_refresh_checkbox = JCheckBox("Auto-refresh mirrors when primary refreshes", True)
        options_panel.add(self._auto_refresh_checkbox)
        settings.add(options_panel)
        settings.add(JLabel(" "))
        
        # === RESOURCE LIMITS SECTION ===
        limits_panel = JPanel()
        limits_panel.setLayout(BoxLayout(limits_panel, BoxLayout.Y_AXIS))
        limits_panel.setBorder(BorderFactory.createTitledBorder("Resource Limits"))
        limits_panel.setMaximumSize(Dimension(800, 180))
        
        # Max results row
        max_results_row = JPanel(FlowLayout(FlowLayout.LEFT))
        max_results_row.add(JLabel("Max stored results:"))
        self._max_results_field = JTextField(str(self._max_results), 8)
        self._max_results_field.setToolTipText("Maximum number of results to keep (oldest are removed when exceeded)")
        max_results_row.add(self._max_results_field)
        max_results_row.add(JLabel("  (oldest auto-removed when exceeded)"))
        limits_panel.add(max_results_row)
        
        # Max concurrent threads row
        max_threads_row = JPanel(FlowLayout(FlowLayout.LEFT))
        max_threads_row.add(JLabel("Max concurrent mirrors:"))
        self._max_threads_field = JTextField(str(self._max_concurrent_mirrors), 8)
        self._max_threads_field.setToolTipText("Maximum number of simultaneous mirror requests")
        max_threads_row.add(self._max_threads_field)
        max_threads_row.add(JLabel("  (requests skipped when exceeded)"))
        limits_panel.add(max_threads_row)
        
        # Request timeout row
        timeout_row = JPanel(FlowLayout(FlowLayout.LEFT))
        timeout_row.add(JLabel("Request timeout (seconds):"))
        self._timeout_field = JTextField(str(self._request_timeout), 8)
        self._timeout_field.setToolTipText("How long to wait for mirror responses before timing out")
        timeout_row.add(self._timeout_field)
        timeout_row.add(JLabel("  (per mirror request)"))
        limits_panel.add(timeout_row)
        
        # Diff limit row
        diff_limit_row = JPanel(FlowLayout(FlowLayout.LEFT))
        diff_limit_row.add(JLabel("Max diff lines:"))
        self._diff_limit_field = JTextField(str(self._max_diff_lines), 8)
        self._diff_limit_field.setToolTipText("Maximum lines to show in diff view (prevents UI freeze on large responses)")
        diff_limit_row.add(self._diff_limit_field)
        diff_limit_row.add(JLabel("  (prevents UI freeze on large responses)"))
        limits_panel.add(diff_limit_row)
        
        settings.add(limits_panel)
        settings.add(JLabel(" "))
        
        # Save
        save_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        save_btn = JButton("Save Settings")
        save_btn.addActionListener(lambda e: self._save_settings())
        save_panel.add(save_btn)
        
        # Reset to defaults button
        reset_btn = JButton("Reset to Defaults")
        reset_btn.addActionListener(lambda e: self._reset_settings_to_defaults())
        save_panel.add(reset_btn)
        
        settings.add(save_panel)
        
        panel.add(JScrollPane(settings), BorderLayout.CENTER)
        return panel
    
    def _save_settings(self):
        """Save settings"""
        # Tool interception flags
        self.mirror_from_proxy = self._proxy_checkbox.isSelected()
        self.mirror_from_repeater = self._repeater_checkbox.isSelected()
        self.mirror_from_scanner = self._scanner_checkbox.isSelected()
        self.mirror_from_intruder = self._intruder_checkbox.isSelected()
        self.mirror_from_extender = self._extender_checkbox.isSelected()
        
        # Pattern settings
        self.login_patterns = [p.strip() for p in self._login_patterns_field.getText().split(",") if p.strip()]
        self.refresh_patterns = [p.strip() for p in self._refresh_patterns_field.getText().split(",") if p.strip()]
        self.token_keys = [k.strip() for k in self._token_keys_field.getText().split(",") if k.strip()]
        self.auto_refresh_mirrors = self._auto_refresh_checkbox.isSelected()
        
        # Resource limits (with validation)
        try:
            max_results = int(self._max_results_field.getText().strip())
            if max_results < 10:
                max_results = 10
            elif max_results > 100000:
                max_results = 100000
            self._max_results = max_results
        except:
            self._log("Invalid max results value, keeping current: " + str(self._max_results))
        
        try:
            max_threads = int(self._max_threads_field.getText().strip())
            if max_threads < 1:
                max_threads = 1
            elif max_threads > 50:
                max_threads = 50
            self._max_concurrent_mirrors = max_threads
        except:
            self._log("Invalid max threads value, keeping current: " + str(self._max_concurrent_mirrors))
        
        try:
            timeout = int(self._timeout_field.getText().strip())
            if timeout < 1:
                timeout = 1
            elif timeout > 120:
                timeout = 120
            self._request_timeout = timeout
        except:
            self._log("Invalid timeout value, keeping current: " + str(self._request_timeout))
        
        try:
            diff_lines = int(self._diff_limit_field.getText().strip())
            if diff_lines < 50:
                diff_lines = 50
            elif diff_lines > 10000:
                diff_lines = 10000
            self._max_diff_lines = diff_lines
        except:
            self._log("Invalid diff lines value, keeping current: " + str(self._max_diff_lines))
        
        # Update UI fields to show validated values
        self._max_results_field.setText(str(self._max_results))
        self._max_threads_field.setText(str(self._max_concurrent_mirrors))
        self._timeout_field.setText(str(self._request_timeout))
        self._diff_limit_field.setText(str(self._max_diff_lines))
        
        # Log what's enabled
        enabled_tools = []
        if self.mirror_from_proxy: enabled_tools.append("Proxy")
        if self.mirror_from_repeater: enabled_tools.append("Repeater")
        if self.mirror_from_scanner: enabled_tools.append("Scanner")
        if self.mirror_from_intruder: enabled_tools.append("Intruder")
        if self.mirror_from_extender: enabled_tools.append("Extensions")
        
        self._log("Settings saved. Tools: " + (", ".join(enabled_tools) if enabled_tools else "NONE"))
        self._log("  Limits: max_results={}, max_threads={}, timeout={}s, diff_lines={}".format(
            self._max_results, self._max_concurrent_mirrors, self._request_timeout, self._max_diff_lines))
    
    def _reset_settings_to_defaults(self):
        """Reset all settings to default values"""
        # Tool interception
        self._proxy_checkbox.setSelected(True)
        self._repeater_checkbox.setSelected(False)
        self._scanner_checkbox.setSelected(False)
        self._intruder_checkbox.setSelected(False)
        self._extender_checkbox.setSelected(False)
        
        # Patterns
        default_login = ["/login", "/signin", "/auth", "/authenticate", "/oauth", 
                        "/token", "/session", "/api/login", "/api/auth", "/api/token"]
        default_refresh = ["/refresh", "/token/refresh", "/auth/refresh"]
        default_tokens = ["access_token", "accessToken", "token", "id_token", "jwt", "bearer"]
        
        self._login_patterns_field.setText(", ".join(default_login))
        self._refresh_patterns_field.setText(", ".join(default_refresh))
        self._token_keys_field.setText(", ".join(default_tokens))
        
        # Options
        self._auto_refresh_checkbox.setSelected(True)
        
        # Resource limits
        self._max_results_field.setText("1000")
        self._max_threads_field.setText("10")
        self._timeout_field.setText("15")
        self._diff_limit_field.setText("500")
        
        self._log("Settings reset to defaults (click Save to apply)")
    
    def _build_log_panel(self):
        """Build log panel"""
        panel = JPanel(BorderLayout(10, 10))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        self._log_area = JTextArea(25, 70)
        self._log_area.setEditable(False)
        self._log_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        panel.add(JScrollPane(self._log_area), BorderLayout.CENTER)
        
        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        clear_btn = JButton("Clear Logs")
        clear_btn.addActionListener(lambda e: self._log_area.setText(""))
        btn_panel.add(clear_btn)
        
        btn_panel.add(JLabel("    "))
        
        self._debug_checkbox = JCheckBox("Enable Debug Logging", False)
        self._debug_checkbox.setToolTipText("Show verbose debug messages (generates lots of output)")
        self._debug_checkbox.addActionListener(lambda e: self._toggle_debug())
        btn_panel.add(self._debug_checkbox)
        
        panel.add(btn_panel, BorderLayout.SOUTH)
        
        return panel
    
    def _toggle_debug(self):
        """Toggle debug mode"""
        self.debug_mode = self._debug_checkbox.isSelected()
        self._log("Debug logging " + ("ENABLED" if self.debug_mode else "DISABLED"))
    
    def _debug_log(self, message):
        """Log debug message (only if debug mode is enabled)"""
        if not self.debug_mode:
            return
        self._log("[DEBUG] " + message)
    
    def _debug_print(self, message):
        """Print debug message to console (only if debug mode is enabled)"""
        if not self.debug_mode:
            return
        print("[DM DEBUG] " + message)
    
    def _add_result(self, result):
        """Add a result with automatic cleanup if over limit"""
        with self.results_lock:
            # Remove oldest results if we're at the limit
            while self.results.size() >= self._max_results:
                self.results.remove(0)  # Remove oldest
            self.results.add(result)
    
    def _refresh_domain_table(self):
        """Refresh domain table while preserving selection"""
        def do_refresh():
            # Save selection
            selected_row = self._domain_table.getSelectedRow()
            
            # Refresh
            self._domain_model.fireTableDataChanged()
            
            # Restore selection if valid
            if selected_row >= 0 and selected_row < self._domain_model.getRowCount():
                self._domain_table.setRowSelectionInterval(selected_row, selected_row)
        
        SwingUtilities.invokeLater(do_refresh)
    
    def _refresh_results_table(self):
        """Refresh results table while preserving selection"""
        def do_refresh():
            # Save selection
            selected_row = self._results_table.getSelectedRow()
            
            # Refresh
            self._results_model.fireTableDataChanged()
            if hasattr(self, '_update_results_count'):
                self._update_results_count()
            
            # Restore selection if valid
            if selected_row >= 0 and selected_row < self._results_model.getRowCount():
                self._results_table.setRowSelectionInterval(selected_row, selected_row)
        
        SwingUtilities.invokeLater(do_refresh)
    
    def _can_start_mirror_thread(self):
        """Check if we can start another mirror thread"""
        with self._mirror_thread_lock:
            if self._active_mirror_threads >= self._max_concurrent_mirrors:
                return False
            self._active_mirror_threads += 1
            return True
    
    def _mirror_thread_finished(self):
        """Mark a mirror thread as finished"""
        with self._mirror_thread_lock:
            self._active_mirror_threads = max(0, self._active_mirror_threads - 1)
    
    def _log(self, message):
        """Log message"""
        ts = time.strftime("%H:%M:%S")
        log_msg = "[" + ts + "] " + message + "\n"
        print("[Domain Mirror] " + message)
        
        def update():
            self._log_area.append(log_msg)
            self._log_area.setCaretPosition(self._log_area.getDocument().getLength())
        
        SwingUtilities.invokeLater(update)
    
    # === ITab ===
    
    def getTabCaption(self):
        return "Domain Mirror"
    
    def getUiComponent(self):
        return self._main_panel
    
    # === Listeners ===
    
    def processProxyMessage(self, messageIsRequest, message):
        """Process proxy messages"""
        # Basic logging to confirm listener is active (only in debug mode)
        if self.debug_mode and not messageIsRequest:
            try:
                info = message.getMessageInfo()
                service = info.getHttpService()
                if service:
                    host = service.getHost()
                    domain_count = self.domains.size()
                    self._debug_log("PROXY: " + host + " (domains: " + str(domain_count) + ")")
            except:
                pass
        
        try:
            info = message.getMessageInfo()
            service = info.getHttpService()
            if not service:
                return
            
            host = service.getHost()
            
            # Debug: Log when we see traffic from tracked domains
            entry = self._get_domain_entry(host)
            
            if not entry:
                return
            
            # WE FOUND A MATCH!
            self._debug_log("MATCHED: " + host + " -> " + entry["domain"])
            
            if messageIsRequest:
                self._capture_from_request(host, info.getRequest(), entry)
            else:
                # This is a RESPONSE from a tracked domain
                self._debug_print("Processing RESPONSE for: " + host)
                self._debug_print("mirror_enabled = " + str(self.mirror_enabled))
                self._debug_print("mirror_from_proxy = " + str(self.mirror_from_proxy))
                self._debug_print("is_primary = " + str(entry["is_primary"]))
                
                is_primary = entry["is_primary"]
                
                # FIRST: Check if we should mirror (before any other processing)
                # Now also checks the mirror_from_proxy flag
                if self.mirror_enabled and is_primary and self.mirror_from_proxy:
                    self._debug_print("WILL MIRROR!")
                    mirrors = self._get_mirror_domains()
                    self._debug_print("Found " + str(len(mirrors)) + " mirror domains")
                    
                    if mirrors:
                        # Get request/response bytes NOW while we're in the callback
                        self._debug_print("Getting request bytes...")
                        request_bytes = info.getRequest()
                        self._debug_print("Got request bytes: " + str(len(request_bytes) if request_bytes else 0))
                        
                        self._debug_print("Getting response bytes...")
                        response_bytes = info.getResponse()
                        self._debug_print("Got response bytes: " + str(len(response_bytes) if response_bytes else 0))
                        
                        # Get path by parsing first line manually (avoid analyzeRequest blocking)
                        self._debug_print("Parsing request manually...")
                        try:
                            request_str = self._helpers.bytesToString(request_bytes)
                            first_line = request_str.split("\r\n")[0] if "\r\n" in request_str else request_str.split("\n")[0]
                            # First line is like "GET /path HTTP/1.1"
                            parts = first_line.split(" ")
                            path = parts[1] if len(parts) >= 2 else "/"
                            self._debug_print("Path: " + path)
                        except Exception as e:
                            self._debug_print("Parse failed: " + str(e))
                            path = "/unknown"
                        
                        # Get service info
                        protocol = service.getProtocol()
                        port = service.getPort()
                        self._debug_print("Service: " + protocol + "://" + host + ":" + str(port))
                        
                        self._log(">>> MIRRORING: " + path + " to " + str(len(mirrors)) + " mirror(s)")
                        
                        # Check if we can start another thread
                        if not self._can_start_mirror_thread():
                            self._log("WARNING: Too many concurrent mirrors, skipping")
                            return
                        
                        self._debug_print("Starting mirror thread...")
                        
                        # Capture ALL needed data for the thread
                        def do_mirror(req_bytes=request_bytes, resp_bytes=response_bytes, 
                                     src_host=host, src_protocol=protocol, src_port=port,
                                     mirror_list=mirrors):
                            try:
                                self._debug_print("Mirror thread started!")
                                self._mirror_request_v2(req_bytes, resp_bytes, src_host, 
                                                       src_protocol, src_port, mirror_list)
                                self._debug_print("Mirror thread completed!")
                            except Exception as e:
                                self._debug_print("Mirror thread EXCEPTION: " + str(e))
                                self._log("Mirror thread error: " + str(e))
                                import traceback
                                traceback.print_exc()
                            finally:
                                self._mirror_thread_finished()
                        
                        t = Thread(target=do_mirror)
                        t.daemon = True  # Allow JVM to exit even if thread is running
                        t.start()
                        self._debug_print("Thread started OK")
                    else:
                        self._log("WARNING: No mirror domains configured!")
                else:
                    self._debug_print("NOT mirroring - mirror_enabled=" + str(self.mirror_enabled) + " is_primary=" + str(is_primary) + " mirror_from_proxy=" + str(self.mirror_from_proxy))
                
                # THEN: Do session capture (after mirroring is triggered)
                try:
                    self._capture_from_response(host, info.getRequest(), info.getResponse(), entry)
                except Exception as e:
                    self._debug_print("_capture_from_response EXCEPTION: " + str(e))
                    
        except Exception as e:
            self._log("processProxyMessage error: " + str(e))
            import traceback
            traceback.print_exc()
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Process HTTP messages from various Burp tools"""
        service = messageInfo.getHttpService()
        if not service:
            return
        
        # Skip our own mirror requests to prevent infinite loops
        if messageIsRequest:
            try:
                request_bytes = messageInfo.getRequest()
                if request_bytes:
                    request_str = self._helpers.bytesToString(request_bytes)
                    if "X-DomainMirror-Internal: true" in request_str:
                        return  # This is our own request, skip it
            except:
                pass
        
        host = service.getHost()
        entry = self._get_domain_entry(host)
        if not entry:
            return
        
        # Always capture sessions regardless of tool
        if messageIsRequest:
            self._capture_from_request(host, messageInfo.getRequest(), entry)
        else:
            self._capture_from_response(host, messageInfo.getRequest(), messageInfo.getResponse(), entry)
            
            # Check if we should mirror from this tool
            should_mirror = self._should_mirror_from_tool(toolFlag)
            
            if should_mirror and self.mirror_enabled and entry["is_primary"]:
                mirrors = self._get_mirror_domains()
                
                if mirrors:
                    request_bytes = messageInfo.getRequest()
                    response_bytes = messageInfo.getResponse()
                    
                    if request_bytes and response_bytes:
                        # Double-check this isn't our own request
                        try:
                            request_str = self._helpers.bytesToString(request_bytes)
                            if "X-DomainMirror-Internal: true" in request_str:
                                return  # Skip our own requests
                        except:
                            pass
                        
                        # Get tool name for logging
                        tool_name = self._get_tool_name(toolFlag)
                        
                        # Parse path
                        try:
                            request_str = self._helpers.bytesToString(request_bytes)
                            first_line = request_str.split("\r\n")[0] if "\r\n" in request_str else request_str.split("\n")[0]
                            parts = first_line.split(" ")
                            path = parts[1] if len(parts) >= 2 else "/"
                        except:
                            path = "/unknown"
                        
                        protocol = service.getProtocol()
                        port = service.getPort()
                        
                        self._log("[" + tool_name + "] >>> MIRRORING: " + path + " to " + str(len(mirrors)) + " mirror(s)")
                        
                        # Check if we can start another thread
                        if not self._can_start_mirror_thread():
                            self._log("WARNING: Too many concurrent mirrors, skipping")
                            return
                        
                        def do_mirror(req_bytes=request_bytes, resp_bytes=response_bytes,
                                     src_host=host, src_protocol=protocol, src_port=port,
                                     mirror_list=mirrors, tool=tool_name):
                            try:
                                self._mirror_request_v2(req_bytes, resp_bytes, src_host,
                                                       src_protocol, src_port, mirror_list)
                            except Exception as e:
                                self._log("[" + tool + "] Mirror error: " + str(e))
                            finally:
                                self._mirror_thread_finished()
                        
                        t = Thread(target=do_mirror)
                        t.daemon = True
                        t.start()
    
    def _should_mirror_from_tool(self, toolFlag):
        """Check if we should mirror requests from this tool"""
        # Skip Proxy here - it's handled in processProxyMessage
        if toolFlag == TOOL_PROXY:
            return False  # Don't double-process proxy
        
        if toolFlag == TOOL_REPEATER and self.mirror_from_repeater:
            return True
        if toolFlag == TOOL_SCANNER and self.mirror_from_scanner:
            return True
        if toolFlag == TOOL_INTRUDER and self.mirror_from_intruder:
            return True
        if toolFlag == TOOL_EXTENDER and self.mirror_from_extender:
            return True
        
        return False
    
    def _get_tool_name(self, toolFlag):
        """Get human-readable tool name"""
        tool_names = {
            TOOL_PROXY: "Proxy",
            TOOL_REPEATER: "Repeater",
            TOOL_SCANNER: "Scanner",
            TOOL_INTRUDER: "Intruder",
            TOOL_EXTENDER: "Extension"
        }
        return tool_names.get(toolFlag, "Tool-" + str(toolFlag))
    
    def _get_domain_entry(self, host):
        """Get domain entry"""
        # Use print for immediate output (bypasses async logging)
        self._debug_print("_get_domain_entry called with host: " + str(host))
        
        with self.domains_lock:
            size = self.domains.size()
            self._debug_print("domains.size() = " + str(size))
            
            if size == 0:
                self._debug_print("domains list is EMPTY!")
                return None
            
            for i in range(size):
                e = self.domains.get(i)
                domain = e["domain"]
                self._debug_print("Comparing '" + str(host) + "' with '" + str(domain) + "'")
                
                # Check exact match
                if domain == host:
                    self._debug_print("EXACT MATCH!")
                    return e
                # Check subdomain match
                if host.endswith("." + domain):
                    self._debug_print("SUBDOMAIN MATCH!")
                    return e
            
            self._debug_print("No match found")
        
        return None
    
    def _get_primary_domain(self):
        """Get primary domain"""
        with self.domains_lock:
            for i in range(self.domains.size()):
                if self.domains.get(i)["is_primary"]:
                    return self.domains.get(i)
        return None
    
    def _get_mirror_domains(self):
        """Get mirror domains"""
        mirrors = []
        with self.domains_lock:
            for i in range(self.domains.size()):
                if not self.domains.get(i)["is_primary"]:
                    mirrors.append(self.domains.get(i))
        return mirrors
    
    def _capture_from_request(self, host, request, entry):
        """Capture session from request based on auth mode"""
        if not request:
            return
        
        auth_mode = entry["auth_mode"]
        session = entry["session"]
        
        # Skip if auth mode is None or Custom (custom is manually set)
        if auth_mode == AUTH_NONE:
            return
        
        request_info = self._helpers.analyzeRequest(request)
        headers = request_info.getHeaders()
        updated = False
        
        for header in headers:
            header_lower = header.lower()
            
            # Capture bearer if applicable
            if header_lower.startswith("authorization:"):
                if auth_mode in [AUTH_AUTO, AUTH_BEARER, AUTH_BOTH]:
                    auth_val = header.split(":", 1)[1].strip()
                    if auth_val.lower().startswith("bearer "):
                        token = auth_val[7:]
                        if token != session["bearer"]:
                            session["bearer"] = token
                            session["last_updated"] = time.time()
                            self._extract_token_expiry(session, token)
                            updated = True
                            self._log("Captured bearer: " + host)
            
            # Capture cookies if applicable
            elif header_lower.startswith("cookie:"):
                if auth_mode in [AUTH_AUTO, AUTH_COOKIES, AUTH_BOTH]:
                    cookie_str = header.split(":", 1)[1].strip()
                    for cookie in cookie_str.split(";"):
                        cookie = cookie.strip()
                        if "=" in cookie:
                            name, value = cookie.split("=", 1)
                            if session["cookies"].get(name.strip()) != value.strip():
                                session["cookies"][name.strip()] = value.strip()
                                updated = True
                    
                    if updated:
                        session["last_updated"] = time.time()
        
        if updated:
            self._update_session_status(session, auth_mode)
            self._refresh_domain_table()
    
    def _capture_from_response(self, host, request, response, entry):
        """Capture session from response"""
        if not response:
            return
        
        auth_mode = entry["auth_mode"]
        session = entry["session"]
        
        if auth_mode == AUTH_NONE:
            return
        
        request_info = self._helpers.analyzeRequest(request) if request else None
        response_info = self._helpers.analyzeResponse(response)
        headers = response_info.getHeaders()
        
        request_path = ""
        if request_info:
            url = request_info.getUrl()
            request_path = url.getPath() if url else ""
        
        is_refresh = any(p in request_path.lower() for p in self.refresh_patterns)
        updated = False
        
        # Capture Set-Cookie
        if auth_mode in [AUTH_AUTO, AUTH_COOKIES, AUTH_BOTH]:
            for header in headers:
                if header.lower().startswith("set-cookie:"):
                    cookie_str = header.split(":", 1)[1].strip()
                    cookie_part = cookie_str.split(";")[0].strip()
                    if "=" in cookie_part:
                        name, value = cookie_part.split("=", 1)
                        session["cookies"][name.strip()] = value.strip()
                        session["last_updated"] = time.time()
                        updated = True
        
        # Parse body for tokens
        if auth_mode in [AUTH_AUTO, AUTH_BEARER, AUTH_BOTH]:
            body_offset = response_info.getBodyOffset()
            body = self._helpers.bytesToString(response[body_offset:])
            
            if body.strip().startswith("{"):
                if self._extract_tokens_from_json(session, body, host):
                    updated = True
        
        if updated:
            self._update_session_status(session, auth_mode)
            self._refresh_domain_table()
            SwingUtilities.invokeLater(lambda: self._update_session_detail())
        
        # Trigger mirror refresh
        if is_refresh and entry["is_primary"] and self.auto_refresh_mirrors:
            self._log("Primary refreshed - updating mirrors...")
            for mirror in self._get_mirror_domains():
                def start_refresh(m=mirror["domain"]):
                    t = Thread(target=lambda: self._trigger_refresh(m))
                    t.daemon = True
                    t.start()
                start_refresh()
    
    def _update_session_status(self, session, auth_mode):
        """Update session status based on what's captured"""
        has_cookies = bool(session.get("cookies"))
        has_bearer = bool(session.get("bearer"))
        
        if auth_mode == AUTH_AUTO:
            if has_bearer or has_cookies:
                session["status"] = "ready"
            else:
                session["status"] = "waiting"
        elif auth_mode == AUTH_COOKIES:
            session["status"] = "ready" if has_cookies else "capturing" if has_bearer else "waiting"
        elif auth_mode == AUTH_BEARER:
            session["status"] = "ready" if has_bearer else "capturing" if has_cookies else "waiting"
        elif auth_mode == AUTH_BOTH:
            if has_cookies and has_bearer:
                session["status"] = "ready"
            elif has_cookies or has_bearer:
                session["status"] = "capturing"
            else:
                session["status"] = "waiting"
        elif auth_mode == AUTH_CUSTOM:
            session["status"] = "ready"  # Custom is always ready
        elif auth_mode == AUTH_NONE:
            session["status"] = "ready"  # None is always ready
    
    def _extract_tokens_from_json(self, session, body, host):
        """Extract tokens from JSON"""
        try:
            data = json.loads(body)
            updated = False
            
            def find_value(d, keys):
                for key in keys:
                    if key in d:
                        return d[key]
                    if "data" in d and isinstance(d["data"], dict) and key in d["data"]:
                        return d["data"][key]
                    if "result" in d and isinstance(d["result"], dict) and key in d["result"]:
                        return d["result"][key]
                return None
            
            token = find_value(data, self.token_keys)
            if token and token != session["bearer"]:
                session["bearer"] = token
                session["last_updated"] = time.time()
                self._extract_token_expiry(session, token)
                updated = True
                self._log("Captured token from response: " + host)
            
            refresh = find_value(data, self.refresh_token_keys)
            if refresh and refresh != session["refresh_token"]:
                session["refresh_token"] = refresh
                session["last_updated"] = time.time()
                updated = True
            
            return updated
        except:
            return False
    
    def _extract_token_expiry(self, session, token):
        """Extract JWT expiry"""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return
            
            payload = parts[1]
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += "=" * padding
            
            decoded = base64.b64decode(payload)
            claims = json.loads(decoded)
            
            if "exp" in claims:
                session["token_expiry"] = claims["exp"]
        except:
            pass
    
    def _trigger_refresh(self, domain):
        """Trigger token refresh"""
        with self.pending_refresh_lock:
            if domain in self.pending_refresh:
                return
            self.pending_refresh.add(domain)
        
        try:
            entry = self._get_domain_entry(domain)
            if not entry:
                return
            
            session = entry["session"]
            refresh_token = session.get("refresh_token", "")
            cookies = session.get("cookies", {})
            
            if not refresh_token and not cookies:
                return
            
            refresh_path = self.refresh_patterns[0] if self.refresh_patterns else "/auth/refresh"
            
            headers = [
                "POST " + refresh_path + " HTTP/1.1",
                "Host: " + domain,
                "Content-Type: application/json"
            ]
            
            if cookies and entry["auth_mode"] in [AUTH_AUTO, AUTH_COOKIES, AUTH_BOTH]:
                cookie_str = "; ".join([k + "=" + v for k, v in cookies.items()])
                headers.append("Cookie: " + cookie_str)
            
            if session.get("bearer") and entry["auth_mode"] in [AUTH_AUTO, AUTH_BEARER, AUTH_BOTH]:
                headers.append("Authorization: Bearer " + session["bearer"])
            
            body = json.dumps({"refresh_token": refresh_token}) if refresh_token else "{}"
            request = self._helpers.buildHttpMessage(headers, body)
            service = self._helpers.buildHttpService(domain, 443, True)
            
            response = self._callbacks.makeHttpRequest(service, request)
            if response and response.getResponse():
                self._capture_from_response(domain, request, response.getResponse(), entry)
                self._log("Refreshed: " + domain)
        
        except Exception as e:
            self._log("Refresh error " + domain + ": " + str(e))
        
        finally:
            with self.pending_refresh_lock:
                self.pending_refresh.discard(domain)
    
    def _mirror_request(self, original_message, primary_domain):
        """Mirror request to mirrors"""
        try:
            self._log("_mirror_request started for: " + primary_domain)
            
            service = original_message.getHttpService()
            request = original_message.getRequest()
            response = original_message.getResponse()
            
            if not request:
                self._log("ERROR: No request data!")
                return
            if not response:
                self._log("ERROR: No response data!")
                return
            
            request_info = self._helpers.analyzeRequest(request)
            url = request_info.getUrl()
            path = url.getPath()
            if url.getQuery():
                path += "?" + url.getQuery()
            
            headers = request_info.getHeaders()
            method = headers[0].split(" ")[0] if headers else "GET"
            
            self._log("Processing: " + method + " " + path)
            
            # Skip refresh endpoints
            if any(p in path.lower() for p in self.refresh_patterns):
                self._log("Skipping refresh endpoint")
                return
            
            response_info = self._helpers.analyzeResponse(response)
            body_offset = response_info.getBodyOffset()
            primary_body = self._helpers.bytesToString(response[body_offset:])
            primary_hash = hashlib.md5(primary_body.encode('utf-8', errors='ignore')).hexdigest()
            
            result = {
                "method": method,
                "path": path,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "match": True,
                "responses": {
                    primary_domain: {
                        "hash": primary_hash,
                        "status": response_info.getStatusCode(),
                        "size": len(primary_body),
                        "body": primary_body
                    }
                }
            }
            
            mirrors = self._get_mirror_domains()
            self._log("Found " + str(len(mirrors)) + " mirror domains")
            
            hashes = [primary_hash]
            
            for mirror_entry in mirrors:
                mirror_domain = mirror_entry["domain"]
                mirror_session = mirror_entry["session"]
                
                # Warn if mirror has no session (likely to cause 302s)
                if not mirror_session.get("cookies") and not mirror_session.get("bearer"):
                    self._log("WARNING: " + mirror_domain + " has no captured session! May get 302 redirects.")
                    self._log("  -> Browse to https://" + mirror_domain + " and log in first")
                
                self._log("Mirroring to: " + mirror_domain)
                
                try:
                    # Build mirrored request
                    mirrored_req = self._build_mirrored_request(request, mirror_entry)
                    
                    if not mirrored_req:
                        self._log("ERROR: Failed to build mirrored request for " + mirror_domain)
                        continue
                    
                    # Determine protocol and port
                    use_https = service.getProtocol() == "https"
                    port = 443 if use_https else 80
                    
                    self._log("Sending to " + mirror_domain + ":" + str(port) + " (https=" + str(use_https) + ")")
                    
                    # Create service for mirror
                    mirror_service = self._helpers.buildHttpService(mirror_domain, port, use_https)
                    
                    # Make the request WITH TIMEOUT
                    mirror_resp, error = self._make_request_with_timeout(mirror_service, mirrored_req, self._request_timeout)
                    
                    if error:
                        self._log("ERROR for " + mirror_domain + ": " + error)
                        continue
                    
                    if not mirror_resp:
                        self._log("ERROR: No response object from " + mirror_domain)
                        continue
                    
                    resp_bytes = mirror_resp.getResponse()
                    if not resp_bytes:
                        self._log("ERROR: Empty response from " + mirror_domain)
                        continue
                    
                    self._log("Got response from " + mirror_domain + " (" + str(len(resp_bytes)) + " bytes)")
                    
                    mir_info = self._helpers.analyzeResponse(resp_bytes)
                    mir_offset = mir_info.getBodyOffset()
                    mir_body = self._helpers.bytesToString(resp_bytes[mir_offset:])
                    mir_hash = hashlib.md5(mir_body.encode('utf-8', errors='ignore')).hexdigest()
                    
                    result["responses"][mirror_domain] = {
                        "hash": mir_hash,
                        "status": mir_info.getStatusCode(),
                        "size": len(mir_body),
                        "body": mir_body
                    }
                    
                    hashes.append(mir_hash)
                    
                    # Capture session from response
                    self._capture_from_response(mirror_domain, mirrored_req, resp_bytes, mirror_entry)
                    
                    mir_status = mir_info.getStatusCode()
                    if mir_status in [301, 302, 303, 307, 308]:
                        self._log("Mirrored to " + mirror_domain + ": " + str(mir_status) + " (REDIRECT - session issue?)")
                    else:
                        self._log("Mirrored to " + mirror_domain + ": " + str(mir_status))
                
                except Exception as e:
                    self._log("ERROR mirroring to " + mirror_domain + ": " + str(e))
                    import traceback
                    traceback.print_exc()
            
            result["match"] = len(set(hashes)) == 1
            
            self._add_result(result)
            
            def update_ui():
                self._results_model.fireTableDataChanged()
                if hasattr(self, '_update_results_count'):
                    self._update_results_count()
            
            SwingUtilities.invokeLater(update_ui)
            
            status = "MATCH" if result["match"] else "DIFF"
            self._log("Result: " + status + " " + method + " " + path[:50])
        
        except Exception as e:
            self._log("ERROR in _mirror_request: " + str(e))
            import traceback
            traceback.print_exc()
    
    def _build_mirrored_request(self, original_request, mirror_entry):
        """Build request with mirror's auth"""
        # Manual parsing to avoid Burp API blocking issues
        self._debug_print("_build_mirrored_request called")
        
        request_str = self._helpers.bytesToString(original_request)
        
        # Split headers and body
        if "\r\n\r\n" in request_str:
            header_section, body_str = request_str.split("\r\n\r\n", 1)
            line_sep = "\r\n"
        elif "\n\n" in request_str:
            header_section, body_str = request_str.split("\n\n", 1)
            line_sep = "\n"
        else:
            header_section = request_str
            body_str = ""
            line_sep = "\r\n"
        
        headers = header_section.split(line_sep)
        body = body_str.encode('utf-8') if body_str else None
        
        self._debug_print("Parsed " + str(len(headers)) + " headers, body=" + str(len(body_str)) + " bytes")
        
        mirror_domain = mirror_entry["domain"]
        session = mirror_entry["session"]
        auth_mode = mirror_entry["auth_mode"]
        
        # Debug: Show what session data we have for this mirror
        self._debug_print("Mirror domain: " + mirror_domain)
        self._debug_print("  Auth mode: " + str(auth_mode))
        self._debug_print("  Session status: " + str(session.get("status", "unknown")))
        self._debug_print("  Has cookies: " + str(bool(session.get("cookies"))))
        if session.get("cookies"):
            self._debug_print("  Cookie count: " + str(len(session["cookies"])))
            self._debug_print("  Cookie names: " + ", ".join(session["cookies"].keys()))
        self._debug_print("  Has bearer: " + str(bool(session.get("bearer"))))
        
        new_headers = []
        has_auth = False
        has_cookie = False
        
        for i, header in enumerate(headers):
            if i == 0:
                new_headers.append(header)
            elif header.lower().startswith("host:"):
                new_headers.append("Host: " + mirror_domain)
            elif header.lower().startswith("authorization:"):
                has_auth = True
                if auth_mode in [AUTH_AUTO, AUTH_BEARER, AUTH_BOTH] and session.get("bearer"):
                    new_headers.append("Authorization: Bearer " + session["bearer"])
                    self._debug_print("  Using mirror's bearer token")
                elif auth_mode == AUTH_NONE:
                    self._debug_print("  Skipping auth (mode=NONE)")
                    pass  # Don't add auth
                elif auth_mode == AUTH_COOKIES:
                    self._debug_print("  Skipping auth (mode=COOKIES)")
                    pass  # Don't add bearer
                else:
                    new_headers.append(header)
                    self._debug_print("  WARNING: Using original auth header (no mirror token)")
            elif header.lower().startswith("cookie:"):
                has_cookie = True
                if auth_mode in [AUTH_AUTO, AUTH_COOKIES, AUTH_BOTH] and session.get("cookies"):
                    cookie_str = "; ".join([k + "=" + v for k, v in session["cookies"].items()])
                    new_headers.append("Cookie: " + cookie_str)
                    self._debug_print("  Using mirror's cookies: " + cookie_str[:100] + "...")
                elif auth_mode == AUTH_NONE:
                    self._debug_print("  Skipping cookies (mode=NONE)")
                    pass  # Don't add cookies
                elif auth_mode == AUTH_BEARER:
                    self._debug_print("  Skipping cookies (mode=BEARER)")
                    pass  # Don't add cookies
                else:
                    # WARNING: This uses the PRIMARY domain's cookies!
                    self._debug_print("  WARNING: No mirror cookies - using original (primary) cookies!")
                    self._debug_print("  Original cookie: " + header[:100])
                    new_headers.append(header)
            elif header.lower().startswith(mirror_entry.get("custom_header_name", "").lower() + ":"):
                # Replace custom header if configured
                if auth_mode == AUTH_CUSTOM and mirror_entry.get("custom_header_value"):
                    new_headers.append(mirror_entry["custom_header_name"] + ": " + mirror_entry["custom_header_value"])
                else:
                    new_headers.append(header)
            else:
                new_headers.append(header)
        
        # Add missing auth based on mode
        if auth_mode in [AUTH_AUTO, AUTH_BEARER, AUTH_BOTH]:
            if not has_auth and session.get("bearer"):
                new_headers.append("Authorization: Bearer " + session["bearer"])
                self._debug_print("  Added missing bearer token")
        
        if auth_mode in [AUTH_AUTO, AUTH_COOKIES, AUTH_BOTH]:
            if not has_cookie and session.get("cookies"):
                cookie_str = "; ".join([k + "=" + v for k, v in session["cookies"].items()])
                new_headers.append("Cookie: " + cookie_str)
                self._debug_print("  Added missing cookies: " + cookie_str[:100] + "...")
        
        if auth_mode == AUTH_CUSTOM:
            header_name = mirror_entry.get("custom_header_name", "")
            header_value = mirror_entry.get("custom_header_value", "")
            if header_name and header_value:
                # Check if already added
                has_custom = any(h.lower().startswith(header_name.lower() + ":") for h in new_headers)
                if not has_custom:
                    new_headers.append(header_name + ": " + header_value)
        
        # Add internal marker header to prevent infinite loops when "Extensions" is enabled
        new_headers.append("X-DomainMirror-Internal: true")
        
        return self._helpers.buildHttpMessage(new_headers, body)
    
    def _mirror_request_v2(self, request_bytes, response_bytes, primary_host, protocol, port, mirrors):
        """Mirror request to mirrors - using raw bytes"""
        try:
            self._debug_print("_mirror_request_v2 started")
            
            if not request_bytes or not response_bytes:
                self._debug_print("Missing request or response bytes!")
                return
            
            # Parse request manually to avoid Burp API blocking issues
            self._debug_print("Parsing request manually...")
            request_str = self._helpers.bytesToString(request_bytes)
            lines = request_str.split("\r\n") if "\r\n" in request_str else request_str.split("\n")
            
            # First line: "GET /path HTTP/1.1"
            first_line = lines[0] if lines else "GET / HTTP/1.1"
            parts = first_line.split(" ")
            method = parts[0] if len(parts) >= 1 else "GET"
            path = parts[1] if len(parts) >= 2 else "/"
            
            self._debug_print("Processing: " + method + " " + path)
            
            # Skip refresh endpoints
            if any(p in path.lower() for p in self.refresh_patterns):
                self._debug_print("Skipping refresh endpoint")
                return
            
            # Calculate primary response hash - analyzeResponse seems to work fine
            self._debug_print("Analyzing response...")
            response_info = self._helpers.analyzeResponse(response_bytes)
            body_offset = response_info.getBodyOffset()
            primary_body = self._helpers.bytesToString(response_bytes[body_offset:])
            primary_hash = hashlib.md5(primary_body.encode('utf-8', errors='ignore')).hexdigest()
            self._debug_print("Response analyzed OK")
            
            result = {
                "method": method,
                "path": path,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "match": True,
                "responses": {
                    primary_host: {
                        "hash": primary_hash,
                        "status": response_info.getStatusCode(),
                        "size": len(primary_body),
                        "body": primary_body
                    }
                }
            }
            
            self._debug_print("Primary response: status=" + str(response_info.getStatusCode()) + ", hash=" + primary_hash[:8])
            
            hashes = [primary_hash]
            use_https = (protocol == "https")
            
            # Mirror to each domain
            for mirror_entry in mirrors:
                mirror_domain = mirror_entry["domain"]
                mirror_session = mirror_entry["session"]
                
                # Warn if mirror has no session (likely to cause 302s)
                if not mirror_session.get("cookies") and not mirror_session.get("bearer"):
                    self._log("WARNING: " + mirror_domain + " has no captured session! May get 302 redirects.")
                
                self._debug_print("Mirroring to: " + mirror_domain)
                
                try:
                    # Build mirrored request
                    mirrored_req = self._build_mirrored_request(request_bytes, mirror_entry)
                    
                    if not mirrored_req:
                        self._debug_print("Failed to build request for " + mirror_domain)
                        continue
                    
                    # Determine port
                    mirror_port = 443 if use_https else 80
                    
                    self._debug_print("Sending to " + mirror_domain + ":" + str(mirror_port))
                    
                    # Make request with timeout
                    mirror_service = self._helpers.buildHttpService(mirror_domain, mirror_port, use_https)
                    mirror_resp, error = self._make_request_with_timeout(mirror_service, mirrored_req, self._request_timeout)
                    
                    if error:
                        self._debug_print("Request error: " + error)
                        self._log("Mirror error for " + mirror_domain + ": " + error)
                        continue
                    
                    if not mirror_resp:
                        self._debug_print("No response from " + mirror_domain)
                        continue
                    
                    resp_bytes = mirror_resp.getResponse()
                    if not resp_bytes:
                        self._debug_print("Empty response from " + mirror_domain)
                        continue
                    
                    mir_info = self._helpers.analyzeResponse(resp_bytes)
                    mir_offset = mir_info.getBodyOffset()
                    mir_body = self._helpers.bytesToString(resp_bytes[mir_offset:])
                    mir_hash = hashlib.md5(mir_body.encode('utf-8', errors='ignore')).hexdigest()
                    mir_status = mir_info.getStatusCode()
                    
                    self._debug_print("Mirror response: status=" + str(mir_status) + ", hash=" + mir_hash[:8])
                    
                    result["responses"][mirror_domain] = {
                        "hash": mir_hash,
                        "status": mir_status,
                        "size": len(mir_body),
                        "body": mir_body
                    }
                    
                    hashes.append(mir_hash)
                    
                    # Capture session from response
                    try:
                        self._capture_from_response(mirror_domain, mirrored_req, resp_bytes, mirror_entry)
                    except:
                        pass  # Don't fail mirroring due to session capture
                    
                    # Log with warning for redirects
                    if mir_status in [301, 302, 303, 307, 308]:
                        self._log("Mirrored to " + mirror_domain + ": " + str(mir_status) + " (REDIRECT - session issue?)")
                    else:
                        self._log("Mirrored to " + mirror_domain + ": " + str(mir_status))
                
                except Exception as e:
                    self._debug_print("Exception mirroring to " + mirror_domain + ": " + str(e))
                    import traceback
                    traceback.print_exc()
            
            # Check if all match
            result["match"] = len(set(hashes)) == 1
            
            # Add to results (with automatic cleanup)
            self._add_result(result)
            
            # Update UI
            def update_ui_v2():
                self._results_model.fireTableDataChanged()
                if hasattr(self, '_update_results_count'):
                    self._update_results_count()
            
            SwingUtilities.invokeLater(update_ui_v2)
            
            status = "MATCH" if result["match"] else "DIFF"
            self._log("Result: " + status + " " + method + " " + path[:50])
            self._debug_print("Complete: " + status)
        
        except Exception as e:
            self._debug_print("EXCEPTION: " + str(e))
            import traceback
            traceback.print_exc()
    
    def _test_mirror_manual(self):
        """Manually test mirroring with a simple GET request"""
        self._log("=" * 40)
        self._log("MANUAL MIRROR TEST")
        self._log("=" * 40)
        
        primary = self._get_primary_domain()
        mirrors = self._get_mirror_domains()
        
        if not primary:
            self._log("ERROR: No primary domain configured!")
            JOptionPane.showMessageDialog(self._main_panel, "No primary domain configured!")
            return
        
        if not mirrors:
            self._log("ERROR: No mirror domains configured!")
            JOptionPane.showMessageDialog(self._main_panel, "No mirror domains configured!")
            return
        
        self._log("Primary: " + primary["domain"])
        self._log("Mirrors: " + ", ".join([m["domain"] for m in mirrors]))
        
        # Run test in background thread
        def run_test():
            for mirror_entry in mirrors:
                self._test_single_mirror(mirror_entry)
            
            self._log("")
            self._log("Test complete!")
            self._log("=" * 40)
        
        t = Thread(target=run_test)
        t.daemon = True
        t.start()
        
        JOptionPane.showMessageDialog(self._main_panel, "Test started! Watch the Logs tab.\nNote: Each request has a 10 second timeout.")
    
    def _test_single_mirror(self, mirror_entry):
        """Test a single mirror with timeout"""
        mirror_domain = mirror_entry["domain"]
        self._log("")
        self._log("Testing: " + mirror_domain)
        
        # Result holder for thread communication
        result = {"done": False, "success": False, "message": ""}
        
        def do_request():
            try:
                # Build request
                headers = [
                    "GET / HTTP/1.1",
                    "Host: " + mirror_domain,
                    "User-Agent: BurpSuite-DomainMirror-Test",
                    "Accept: */*",
                    "Connection: close"
                ]
                
                session = mirror_entry["session"]
                auth_mode = mirror_entry.get("auth_mode", "Auto Detect")
                
                if auth_mode in ["Auto Detect", "Bearer Only", "Cookies + Bearer"]:
                    if session.get("bearer"):
                        headers.append("Authorization: Bearer " + session["bearer"][:50] + "...")
                
                if auth_mode in ["Auto Detect", "Cookies Only", "Cookies + Bearer"]:
                    if session.get("cookies"):
                        cookie_str = "; ".join([k + "=" + v for k, v in session["cookies"].items()])
                        headers.append("Cookie: " + cookie_str)
                
                request = self._helpers.buildHttpMessage(headers, None)
                
                # Try HTTPS first
                self._log("  Trying HTTPS (port 443)...")
                mirror_service = self._helpers.buildHttpService(mirror_domain, 443, True)
                response = self._callbacks.makeHttpRequest(mirror_service, request)
                
                if response and response.getResponse():
                    resp_bytes = response.getResponse()
                    resp_info = self._helpers.analyzeResponse(resp_bytes)
                    result["success"] = True
                    result["message"] = "HTTPS OK! Status: " + str(resp_info.getStatusCode())
                else:
                    result["message"] = "HTTPS: No response"
                
            except Exception as e:
                result["message"] = "Error: " + str(e)
            finally:
                result["done"] = True
        
        # Start request thread
        request_thread = Thread(target=do_request)
        request_thread.daemon = True  # Allow JVM to exit
        request_thread.start()
        
        # Wait with timeout (10 seconds)
        timeout = 10
        start = time.time()
        while not result["done"] and (time.time() - start) < timeout:
            time.sleep(0.5)
        
        if not result["done"]:
            self._log("  TIMEOUT after " + str(timeout) + " seconds!")
            self._log("  This usually means:")
            self._log("    - DNS cannot resolve " + mirror_domain)
            self._log("    - Firewall blocking connection")
            self._log("    - Server not responding")
            self._log("  Try: Can you ping " + mirror_domain + " from this machine?")
            self._log("  Try: Can you access https://" + mirror_domain + " in a browser?")
        elif result["success"]:
            self._log("  SUCCESS: " + result["message"])
        else:
            self._log("  FAILED: " + result["message"])
    
    def _make_request_with_timeout(self, service, request, timeout_seconds=10):
        """Make HTTP request with timeout - returns (response, error_message)"""
        result = {"response": None, "error": None, "done": False}
        
        def do_request():
            try:
                result["response"] = self._callbacks.makeHttpRequest(service, request)
            except Exception as e:
                result["error"] = str(e)
            finally:
                result["done"] = True
        
        t = Thread(target=do_request)
        t.daemon = True  # Allow JVM to exit even if thread is hanging
        t.start()
        
        start = time.time()
        while not result["done"] and (time.time() - start) < timeout_seconds:
            time.sleep(0.1)
        
        if not result["done"]:
            return (None, "TIMEOUT after " + str(timeout_seconds) + "s")
        elif result["error"]:
            return (None, result["error"])
        else:
            return (result["response"], None)


# === Domain Config Dialog ===

class DomainConfigDialog(JDialog):
    """Dialog for adding/editing domain configuration"""
    
    def __init__(self, parent, title, extender, existing=None):
        JDialog.__init__(self, SwingUtilities.getWindowAncestor(parent), title, True)
        self.extender = extender
        self.result = None
        self.existing = existing
        
        self._build_dialog()
        self.setSize(500, 350)
        self.setLocationRelativeTo(parent)
    
    def _build_dialog(self):
        """Build dialog UI"""
        panel = JPanel(BorderLayout(10, 10))
        panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15))
        
        # Form
        form = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.anchor = GridBagConstraints.WEST
        
        # Domain
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.weightx = 0
        form.add(JLabel("Domain:"), gbc)
        
        gbc.gridx = 1
        gbc.weightx = 1
        self._domain_field = JTextField(30)
        if self.existing:
            self._domain_field.setText(self.existing["domain"])
        form.add(self._domain_field, gbc)
        
        # Auth Mode
        gbc.gridx = 0
        gbc.gridy = 1
        gbc.weightx = 0
        form.add(JLabel("Auth Mode:"), gbc)
        
        gbc.gridx = 1
        gbc.weightx = 1
        self._auth_mode_combo = JComboBox(AUTH_MODES)
        if self.existing:
            self._auth_mode_combo.setSelectedItem(self.existing.get("auth_mode", AUTH_AUTO))
        self._auth_mode_combo.addActionListener(lambda e: self._on_auth_mode_change())
        form.add(self._auth_mode_combo, gbc)
        
        # Auth mode description
        gbc.gridx = 1
        gbc.gridy = 2
        self._auth_desc = JLabel("<html><i>Auto-detect and use whatever auth is found</i></html>")
        self._auth_desc.setFont(Font("Dialog", Font.PLAIN, 11))
        form.add(self._auth_desc, gbc)
        
        # Custom header section
        gbc.gridx = 0
        gbc.gridy = 3
        gbc.weightx = 0
        self._custom_header_label = JLabel("Header Name:")
        form.add(self._custom_header_label, gbc)
        
        gbc.gridx = 1
        gbc.weightx = 1
        self._custom_header_name = JTextField(20)
        self._custom_header_name.setToolTipText("e.g., X-API-Key")
        if self.existing:
            self._custom_header_name.setText(self.existing.get("custom_header_name", ""))
        form.add(self._custom_header_name, gbc)
        
        gbc.gridx = 0
        gbc.gridy = 4
        gbc.weightx = 0
        self._custom_value_label = JLabel("Header Value:")
        form.add(self._custom_value_label, gbc)
        
        gbc.gridx = 1
        gbc.weightx = 1
        self._custom_header_value = JTextField(30)
        if self.existing:
            self._custom_header_value.setText(self.existing.get("custom_header_value", ""))
        form.add(self._custom_header_value, gbc)
        
        panel.add(form, BorderLayout.CENTER)
        
        # Buttons
        btn_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        
        cancel_btn = JButton("Cancel")
        cancel_btn.addActionListener(lambda e: self._cancel())
        btn_panel.add(cancel_btn)
        
        ok_btn = JButton("OK")
        ok_btn.addActionListener(lambda e: self._ok())
        btn_panel.add(ok_btn)
        
        panel.add(btn_panel, BorderLayout.SOUTH)
        
        self.setContentPane(panel)
        self._on_auth_mode_change()
    
    def _on_auth_mode_change(self):
        """Handle auth mode change"""
        mode = self._auth_mode_combo.getSelectedItem()
        
        descriptions = {
            AUTH_AUTO: "Auto-detect and use whatever auth is found",
            AUTH_COOKIES: "Only transfer cookies between domains",
            AUTH_BEARER: "Only transfer Bearer/JWT token",
            AUTH_BOTH: "Transfer both cookies and Bearer token",
            AUTH_NONE: "Don't transfer any authentication",
            AUTH_CUSTOM: "Use a custom header (e.g., X-API-Key)"
        }
        
        self._auth_desc.setText("<html><i>" + descriptions.get(mode, "") + "</i></html>")
        
        # Show/hide custom header fields
        show_custom = (mode == AUTH_CUSTOM)
        self._custom_header_label.setVisible(show_custom)
        self._custom_header_name.setVisible(show_custom)
        self._custom_value_label.setVisible(show_custom)
        self._custom_header_value.setVisible(show_custom)
    
    def _ok(self):
        """Handle OK"""
        domain = self._domain_field.getText().strip()
        if not domain:
            JOptionPane.showMessageDialog(self, "Please enter a domain")
            return
        
        self.result = {
            "domain": domain,
            "auth_mode": self._auth_mode_combo.getSelectedItem(),
            "custom_header_name": self._custom_header_name.getText().strip(),
            "custom_header_value": self._custom_header_value.getText().strip()
        }
        
        self.dispose()
    
    def _cancel(self):
        """Handle cancel"""
        self.result = None
        self.dispose()


# === Table Models ===

# Custom comparators for table sorting
class NumericComparator(Comparator):
    """Compare strings as numbers"""
    def compare(self, o1, o2):
        try:
            n1 = int(str(o1).replace("#", "").strip()) if o1 else 0
            n2 = int(str(o2).replace("#", "").strip()) if o2 else 0
            return n1 - n2
        except:
            return str(o1).compareTo(str(o2)) if o1 and o2 else 0


class MatchComparator(Comparator):
    """Compare YES/NO values"""
    def compare(self, o1, o2):
        # NO (mismatch) should come before YES (match) in ascending order
        v1 = 0 if str(o1) == "NO" else 1
        v2 = 0 if str(o2) == "NO" else 1
        return v1 - v2


class DomainsComparator(Comparator):
    """Compare domain count strings like '2 domains'"""
    def compare(self, o1, o2):
        try:
            n1 = int(str(o1).split()[0]) if o1 else 0
            n2 = int(str(o2).split()[0]) if o2 else 0
            return n1 - n2
        except:
            return 0


class DomainTableModel(AbstractTableModel):
    """Domain table model"""
    
    COLUMNS = ["Primary", "Domain", "Auth Mode", "Status", "Session Info", "Updated"]
    
    def __init__(self, extender):
        self._extender = extender
    
    def getRowCount(self):
        return self._extender.domains.size()
    
    def getColumnCount(self):
        return len(self.COLUMNS)
    
    def getColumnName(self, col):
        return self.COLUMNS[col]
    
    def getValueAt(self, row, col):
        if row >= self._extender.domains.size():
            return ""
        
        entry = self._extender.domains.get(row)
        session = entry["session"]
        
        if col == 0:
            return "PRIMARY" if entry["is_primary"] else ""
        elif col == 1:
            return entry["domain"]
        elif col == 2:
            return entry.get("auth_mode", AUTH_AUTO)
        elif col == 3:
            return session["status"].upper()
        elif col == 4:
            parts = []
            if session.get("bearer"):
                parts.append("Bearer")
            if session.get("cookies"):
                parts.append(str(len(session["cookies"])) + " cookies")
            if session.get("refresh_token"):
                parts.append("Refresh")
            if entry.get("auth_mode") == AUTH_CUSTOM and entry.get("custom_header_value"):
                parts.append("Custom")
            return ", ".join(parts) if parts else "(none)"
        elif col == 5:
            last = session.get("last_updated")
            return time.strftime("%H:%M:%S", time.localtime(last)) if last else "-"
        
        return ""


class ResultsTableModel(AbstractTableModel):
    """Results table model"""
    
    COLUMNS = ["#", "Method", "Path", "Match", "Domains", "Time"]
    
    def __init__(self, extender):
        self._extender = extender
    
    def getRowCount(self):
        filter_val = "All"
        if hasattr(self._extender, '_filter_combo') and self._extender._filter_combo:
            filter_val = self._extender._filter_combo.getSelectedItem()
        
        count = 0
        for i in range(self._extender.results.size()):
            r = self._extender.results.get(i)
            if filter_val == "All":
                count += 1
            elif filter_val == "Mismatches Only" and not r.get("match"):
                count += 1
            elif filter_val == "Matches Only" and r.get("match"):
                count += 1
        return count
    
    def getColumnCount(self):
        return len(self.COLUMNS)
    
    def getColumnName(self, col):
        return self.COLUMNS[col]
    
    def getValueAt(self, row, col):
        filter_val = "All"
        if hasattr(self._extender, '_filter_combo') and self._extender._filter_combo:
            filter_val = self._extender._filter_combo.getSelectedItem()
        
        filtered_idx = 0
        actual_idx = -1
        
        for i in range(self._extender.results.size()):
            r = self._extender.results.get(i)
            include = (filter_val == "All" or
                      (filter_val == "Mismatches Only" and not r.get("match")) or
                      (filter_val == "Matches Only" and r.get("match")))
            if include:
                if filtered_idx == row:
                    actual_idx = i
                    break
                filtered_idx += 1
        
        if actual_idx < 0:
            return ""
        
        result = self._extender.results.get(actual_idx)
        
        if col == 0:
            return str(actual_idx + 1)
        elif col == 1:
            return result.get("method", "")
        elif col == 2:
            p = result.get("path", "")
            return p[:55] + "..." if len(p) > 55 else p
        elif col == 3:
            return "YES" if result.get("match") else "NO"
        elif col == 4:
            return str(len(result.get("responses", {}))) + " domains"
        elif col == 5:
            ts = result.get("timestamp", "")
            return ts.split(" ")[1] if " " in ts else ts
        
        return ""


# === Renderers ===

class StatusCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col)
        
        if value == "READY":
            c.setBackground(Color(200, 255, 200))
            c.setForeground(Color(0, 100, 0))
        elif value == "CAPTURING":
            c.setBackground(Color(255, 255, 200))
            c.setForeground(Color(150, 100, 0))
        else:
            c.setBackground(Color(255, 220, 220))
            c.setForeground(Color(150, 0, 0))
        
        if isSelected:
            c.setBackground(table.getSelectionBackground())
        
        self.setHorizontalAlignment(SwingConstants.CENTER)
        return c


class AuthModeCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col)
        
        colors = {
            AUTH_AUTO: Color(230, 230, 255),
            AUTH_COOKIES: Color(255, 240, 220),
            AUTH_BEARER: Color(220, 255, 220),
            AUTH_BOTH: Color(255, 220, 255),
            AUTH_NONE: Color(240, 240, 240),
            AUTH_CUSTOM: Color(255, 255, 200)
        }
        
        c.setBackground(colors.get(value, Color.WHITE))
        c.setForeground(Color.BLACK)
        
        if isSelected:
            c.setBackground(table.getSelectionBackground())
        
        return c


class MatchCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col)
        
        if value == "YES":
            c.setBackground(Color(200, 255, 200))
            c.setForeground(Color(0, 100, 0))
        elif value == "NO":
            c.setBackground(Color(255, 180, 180))
            c.setForeground(Color(150, 0, 0))
            c.setFont(c.getFont().deriveFont(Font.BOLD))
        
        if isSelected:
            c.setBackground(table.getSelectionBackground())
        
        self.setHorizontalAlignment(SwingConstants.CENTER)
        return c
