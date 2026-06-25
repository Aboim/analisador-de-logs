import flet as ft
import os
import subprocess
import sys
import tempfile
import threading
from datetime import datetime
from log_analyzer import Database, LogParser, PatternLearner, AnomalyDetector

db = Database()
parser = LogParser()
learner = PatternLearner()
detector = AnomalyDetector()


def main(page: ft.Page):
    page.title = "Analisador de Logs - Auto-Aprendizagem"
    page.window.width = 1300
    page.window.height = 850
    page.window.min_width = 1000
    page.window.min_height = 700
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 0
    page.spacing = 0

    status_text = ft.Text("Pronto", size=12, color=ft.Colors.GREY_400)
    progress_bar = ft.ProgressBar(width=200, visible=False, value=None)
    progress_text = ft.Text("", size=11, color=ft.Colors.BLUE_200)

    alert_dialog_ref = ft.Ref[ft.AlertDialog]()

    summary_stats = ft.Row(spacing=8, wrap=True)

    log_table = ft.DataTable(
        columns=[
            ft.DataColumn(ft.Text("#", size=12)),
            ft.DataColumn(ft.Text("Linha", size=12)),
            ft.DataColumn(ft.Text("Timestamp", size=12)),
            ft.DataColumn(ft.Text("Nivel", size=12)),
            ft.DataColumn(ft.Text("Mensagem", size=12)),
        ],
        column_spacing=8,
        heading_row_height=36,
        data_row_min_height=28,
        data_row_max_height=48,
        expand=True,
    )

    pattern_table = ft.DataTable(
        columns=[
            ft.DataColumn(ft.Text("Freq", size=11)),
            ft.DataColumn(ft.Text("Categoria", size=11)),
            ft.DataColumn(ft.Text("Assinatura", size=11)),
            ft.DataColumn(ft.Text("Conf", size=11)),
        ],
        column_spacing=8,
        heading_row_height=36,
        data_row_min_height=28,
        data_row_max_height=48,
        expand=True,
    )

    anomaly_table = ft.DataTable(
        columns=[
            ft.DataColumn(ft.Text("Timestamp", size=11)),
            ft.DataColumn(ft.Text("Severidade", size=11)),
            ft.DataColumn(ft.Text("Motivo", size=11)),
            ft.DataColumn(ft.Text("Linha", size=11)),
        ],
        column_spacing=8,
        heading_row_height=36,
        data_row_min_height=28,
        data_row_max_height=48,
        expand=True,
    )

    filter_level = ft.Dropdown(
        width=130,
        height=36,
        text_size=12,
        dense=True,
        hint_text="Nivel",
        options=[
            ft.dropdown.Option("ALL", "Todos"),
            ft.dropdown.Option("ERROR", "ERROR"),
            ft.dropdown.Option("WARNING", "WARNING"),
            ft.dropdown.Option("INFO", "INFO"),
            ft.dropdown.Option("DEBUG", "DEBUG"),
            ft.dropdown.Option("CRITICAL", "CRITICAL"),
        ],
        value="ALL",
    )
    filter_level.on_select = lambda e: refresh_log_table()

    filter_anomaly_only = ft.Switch(
        label="So anomalias", value=False, label_text_style=ft.TextStyle(size=12),
    )
    filter_anomaly_only.on_change = lambda e: refresh_log_table()

    filter_problems_only = ft.Switch(
        label="So problemas", value=False, label_text_style=ft.TextStyle(size=12),
    )
    filter_problems_only.on_change = lambda e: refresh_log_table()

    search_field = ft.TextField(
        width=200, height=36, text_size=12, dense=True,
        hint_text="Pesquisar...",
        prefix_icon=ft.Icons.SEARCH,
    )
    search_field.on_change = lambda e: refresh_log_table()

    logs_count_text = ft.Text("0 entradas", size=12, color=ft.Colors.GREY_400)
    patterns_count_text = ft.Text("0 padroes", size=12, color=ft.Colors.GREY_400)
    anomalies_count_text = ft.Text("0 anomalias", size=12, color=ft.Colors.GREY_400)

    selected_file_path = ""
    current_file_id = 0

    stats_content = ft.Column(spacing=10, expand=True, scroll=ft.ScrollMode.AUTO)

    content_areas = ft.Ref[ft.Column]()
    content_logs = ft.Ref[ft.Column]()
    content_patterns = ft.Ref[ft.Column]()
    content_import = ft.Ref[ft.Column]()
    content_anomalies = ft.Ref[ft.Column]()
    content_stats = ft.Ref[ft.Column]()

    def set_status(msg: str, is_error: bool = False):
        status_text.value = msg
        status_text.color = ft.Colors.RED_300 if is_error else ft.Colors.GREY_400
        page.update()

    def show_alert_popup(title: str, content_text: str, severity: str = "medium"):
        icon_map = {
            "critical": ft.Icons.GPP_BAD,
            "high": ft.Icons.ERROR,
            "medium": ft.Icons.WARNING_AMBER,
            "low": ft.Icons.INFO,
        }
        color_map = {
            "critical": ft.Colors.RED_400,
            "high": ft.Colors.RED_300,
            "medium": ft.Colors.ORANGE_300,
            "low": ft.Colors.BLUE_300,
        }
        icon = icon_map.get(severity, ft.Icons.WARNING_AMBER)
        color = color_map.get(severity, ft.Colors.ORANGE_300)

        dialog = ft.AlertDialog(
            ref=alert_dialog_ref,
            modal=False,
            title=ft.Row([
                ft.Icon(icon, color=color, size=24),
                ft.Text(title, size=16, weight=ft.FontWeight.BOLD, color=color),
            ], spacing=10),
            content=ft.Text(content_text, size=13),
            actions=[
                ft.TextButton("OK", on_click=lambda e: page.close(alert_dialog_ref.current)),
                ft.TextButton("Ver Detalhes",
                              on_click=lambda e: (page.close(alert_dialog_ref.current), switch_tab(3))),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )
        page.open(dialog)

    def show_snack(msg: str, color=ft.Colors.GREEN_300):
        page.snack_bar = ft.SnackBar(
            content=ft.Text(msg, size=13),
            bgcolor=color,
            duration=4000,
            action="OK",
            action_color=ft.Colors.WHITE,
        )
        page.snack_bar.open = True
        page.update()

    def set_progress(visible: bool, text: str = ""):
        async def _update():
            progress_bar.visible = visible
            progress_text.value = text
            progress_text.visible = visible
            page.update()
        page.run_task(_update)

    def refresh_summary():
        s = db.get_stats_summary()
        summary_stats.controls = [
            _stat_card("Ficheiros", str(s["total_files"]), ft.Colors.BLUE_200),
            _stat_card("Entradas", str(s["total_entries"]), ft.Colors.CYAN_200),
            _stat_card("Padroes", str(s["total_patterns"]), ft.Colors.GREEN_200),
            _stat_card("Erros", str(s["error_count"]), ft.Colors.RED_300),
            _stat_card("Warnings", str(s["warning_count"]), ft.Colors.ORANGE_300),
            _stat_card("Anomalias", str(s["total_anomalies"]), ft.Colors.PURPLE_300),
        ]
        page.update()

    def _stat_card(label: str, value: str, color) -> ft.Container:
        return ft.Container(
            content=ft.Column([
                ft.Text(label, size=10, color=ft.Colors.GREY_400, text_align=ft.TextAlign.CENTER),
                ft.Text(value, size=22, weight=ft.FontWeight.BOLD, color=color, text_align=ft.TextAlign.CENTER),
            ], alignment=ft.MainAxisAlignment.CENTER, spacing=2, horizontal_alignment=ft.CrossAxisAlignment.CENTER),
            padding=ft.padding.Padding(left=16, top=10, right=16, bottom=10),
            border_radius=8,
            bgcolor=ft.Colors.SURFACE,
            width=120,
        )

    def refresh_log_table():
        level = filter_level.value
        if level == "ALL":
            level = None
        anomaly_only = filter_anomaly_only.value
        problems_only = filter_problems_only.value
        search = search_field.value.strip().lower() if search_field.value else ""

        entries = db.get_log_entries(
            file_id=current_file_id if current_file_id != 0 else None,
            level=level,
            is_anomaly=True if anomaly_only else None,
            limit=500,
        )

        log_table.rows.clear()
        for e in entries:
            if problems_only:
                if not e["is_anomaly"] and e["level"] not in ("ERROR", "CRITICAL", "FATAL", "WARNING", "WARN"):
                    continue
            if search and search not in e["raw_line"].lower():
                continue
            color = None
            if e["is_anomaly"]:
                color = ft.Colors.RED_900
            elif e["level"] in ("ERROR", "CRITICAL", "FATAL"):
                color = ft.Colors.RED_900
            elif e["level"] in ("WARNING", "WARN"):
                color = ft.Colors.AMBER_900

            log_table.rows.append(ft.DataRow(
                cells=[
                    ft.DataCell(ft.Text(str(e["id"]), size=10)),
                    ft.DataCell(ft.Text(str(e.get("line_number", "")), size=10)),
                    ft.DataCell(ft.Text(e["timestamp"][:19] if e["timestamp"] else "", size=10)),
                    ft.DataCell(ft.Text(e["level"], size=10, weight=ft.FontWeight.BOLD,
                                        color=_level_color(e["level"]))),
                    ft.DataCell(ft.Text(e["message"][:120], size=10, max_lines=2,
                                        overflow=ft.TextOverflow.ELLIPSIS,
                                        tooltip=e["raw_line"][:300])),
                ],
                color=color,
            ))

        logs_count_text.value = f"{len(log_table.rows)} entradas"
        page.update()

    def _level_color(level: str):
        colors = {
            "ERROR": ft.Colors.RED_300, "CRITICAL": ft.Colors.RED_400, "FATAL": ft.Colors.RED_500,
            "WARNING": ft.Colors.ORANGE_300, "WARN": ft.Colors.ORANGE_300,
            "INFO": ft.Colors.CYAN_200, "DEBUG": ft.Colors.GREY_400, "TRACE": ft.Colors.GREY_500,
        }
        return colors.get(level.upper(), ft.Colors.GREY_400)

    def refresh_pattern_table():
        patterns = db.get_patterns(limit=300)
        pattern_table.rows.clear()
        for p in patterns:
            category_color = _category_color(p["category"])
            pattern_table.rows.append(ft.DataRow(cells=[
                ft.DataCell(ft.Text(str(p["frequency"]), size=11, weight=ft.FontWeight.BOLD)),
                ft.DataCell(ft.Container(
                    ft.Text(p["category"].upper(), size=10, color=ft.Colors.WHITE),
                    bgcolor=category_color, border_radius=4,
                    padding=ft.padding.Padding(left=6, top=2, right=6, bottom=2),
                )),
                ft.DataCell(ft.Text(p["signature"][:100], size=10, max_lines=1,
                                    overflow=ft.TextOverflow.ELLIPSIS, tooltip=p["signature"])),
                ft.DataCell(ft.Icon(
                    ft.Icons.CHECK_CIRCLE if p["confirmed"] else ft.Icons.SCHEDULE,
                    size=14,
                    color=ft.Colors.GREEN_300 if p["confirmed"] else ft.Colors.GREY_400,
                )),
            ]))
        patterns_count_text.value = f"{len(pattern_table.rows)} padroes"
        page.update()

    def _category_color(cat: str) -> str:
        colors = {
            "error": "#ef4444", "warning": "#f59e0b", "info": "#3b82f6",
            "debug": "#6b7280", "http": "#8b5cf6", "database": "#10b981",
            "system": "#f97316", "auth": "#ec4899", "unknown": "#6b7280",
        }
        return colors.get(cat, "#6b7280")

    def refresh_anomaly_table():
        anomalies = db.get_anomalies(limit=300)
        anomaly_table.rows.clear()
        for a in anomalies:
            sev_color = {
                "critical": ft.Colors.RED_400, "high": ft.Colors.ORANGE_300,
                "medium": ft.Colors.YELLOW_300, "low": ft.Colors.GREY_400,
            }.get(a["severity"], ft.Colors.GREY_400)
            anomaly_table.rows.append(ft.DataRow(cells=[
                ft.DataCell(ft.Text(a.get("timestamp", "")[:19] if a.get("timestamp") else "", size=10)),
                ft.DataCell(ft.Text(a["severity"].upper(), size=10, weight=ft.FontWeight.BOLD, color=sev_color)),
                ft.DataCell(ft.Text(a["reason"][:80], size=10, max_lines=1,
                                    overflow=ft.TextOverflow.ELLIPSIS, tooltip=a["reason"])),
                ft.DataCell(ft.Text(a.get("raw_line", "")[:100], size=10, max_lines=1,
                                    overflow=ft.TextOverflow.ELLIPSIS, tooltip=a.get("raw_line", ""))),
            ]))
        anomalies_count_text.value = f"{len(anomaly_table.rows)} anomalias"
        page.update()

    def refresh_all_tables():
        refresh_log_table()
        refresh_pattern_table()
        refresh_anomaly_table()
        refresh_summary()

    def import_file(filepath: str):
        nonlocal selected_file_path, current_file_id

        if not filepath or not os.path.isfile(filepath):
            set_status("Ficheiro nao encontrado", True)
            return

        filename = os.path.basename(filepath)
        file_size = os.path.getsize(filepath)
        selected_file_path = filepath

        def process():
            nonlocal current_file_id
            set_progress(True, f"A processar {filename}...")

            try:
                entries = parser.parse_file(filepath)
                set_progress(True, f"Analisados {len(entries)} linhas. A aprender padroes...")

                file_id = db.add_log_file(filepath, filename, file_size)
                learner.learn_from_entries(entries, db)
                detector.build_baseline(entries[:1000], db)

                error_count = 0
                warn_count = 0
                info_count = 0
                debug_count = 0
                anomaly_count = 0

                for entry in entries:
                    level = entry.level.upper()
                    if level in ("ERROR", "CRITICAL", "FATAL"):
                        error_count += 1
                    elif level in ("WARNING", "WARN"):
                        warn_count += 1
                    elif level == "DEBUG":
                        debug_count += 1
                    else:
                        info_count += 1

                set_progress(True, "A detetar anomalias...")

                for i, entry in enumerate(entries):
                    if i % 200 == 0:
                        set_progress(True, f"A detetar anomalias... {i}/{len(entries)}")

                    similar = learner.get_similar_patterns(entry.message, db)
                    is_anom, reason, severity, score = detector.detect(
                        entry, pattern_id=getattr(entry, 'pattern_id', 0), similar_patterns=similar
                    )

                    msg = entry.message
                    entry_id = db.insert_log_entry(
                        file_id=file_id,
                        line_number=entry.line_number,
                        timestamp=entry.timestamp,
                        level=entry.level,
                        source=entry.source,
                        message=msg[:1000] if msg else "",
                        raw_line=entry.raw_line[:2000] if entry.raw_line else "",
                        pattern_id=getattr(entry, 'pattern_id', 0),
                        is_anomaly=is_anom,
                        anomaly_score=score,
                    )

                    if is_anom:
                        db.add_anomaly(entry_id, reason, severity)
                        anomaly_count += 1

                db.update_log_file_line_count(file_id, len(entries))
                current_file_id = file_id

                today = datetime.now().strftime("%Y-%m-%d")
                db.upsert_daily_stats(today, len(entries), error_count, warn_count,
                                      info_count, debug_count, anomaly_count)

                page.run_task(_finish_import,
                              filename, len(entries), error_count, warn_count,
                              info_count, debug_count, anomaly_count)

            except Exception as e:
                page.run_task(_finish_import_error, str(e))
            finally:
                page.run_task(_finish_import_progress)

        threading.Thread(target=process, daemon=True).start()

    async def _finish_import(filename: str, total: int, errors: int, warns: int,
                              infos: int, debugs: int, anomalies: int):
        refresh_all_tables()
        set_status(f"Importado: {filename} - {total} linhas, {anomalies} anomalias")

        total_problems = errors + warns + anomalies
        if total_problems > 0:
            sev = "critical" if errors > 0 else ("high" if anomalies > 0 else "medium")
            show_alert_popup(
                f"Problemas Detectados - {filename}",
                f"Foram encontrados {total_problems} problema(s):\n"
                f"  Erros/Criticos: {errors}\n"
                f"  Warnings: {warns}\n"
                f"  Anomalias: {anomalies}\n\n"
                f"Total de {total} linhas analisadas.",
                sev,
            )
            show_snack(
                f"ALERTA: {errors} erros, {warns} warnings, {anomalies} anomalias em {filename}",
                ft.Colors.RED_400 if errors > 0 else ft.Colors.ORANGE_400,
            )
        else:
            show_snack(f"OK: {total} linhas importadas de {filename} sem problemas")

    async def _finish_import_error(error_msg: str):
        set_status(f"Erro: {error_msg}", True)

    async def _finish_import_progress():
        set_progress(False)

    def refresh_stats_view():
        stats_content.controls.clear()
        s = db.get_stats_summary()

        stats_content.controls.append(ft.Text("Resumo Geral", size=18, weight=ft.FontWeight.BOLD))
        stats_content.controls.append(
            ft.Row([
                _stat_card("Ficheiros", str(s["total_files"]), ft.Colors.BLUE_200),
                _stat_card("Entradas", str(s["total_entries"]), ft.Colors.CYAN_200),
                _stat_card("Padroes", str(s["total_patterns"]), ft.Colors.GREEN_200),
                _stat_card("Anomalias", str(s["total_anomalies"]), ft.Colors.PURPLE_300),
            ], spacing=10, wrap=True)
        )

        stats_content.controls.append(ft.Divider(height=20))
        stats_content.controls.append(ft.Text("Distribuicao por Nivel", size=14, weight=ft.FontWeight.BOLD))

        level_dist = db.get_level_distribution()
        for ld in level_dist[:10]:
            pct = (ld["count"] / s["total_entries"] * 100) if s["total_entries"] > 0 else 0
            bar_color = _level_color(ld["level"])
            stats_content.controls.append(
                ft.Row([
                    ft.Text(ld["level"], size=11, width=80, color=bar_color, weight=ft.FontWeight.BOLD),
                    ft.Container(
                        ft.Container(width=max(pct * 2, 2), height=16, bgcolor=bar_color, border_radius=4),
                        expand=True,
                    ),
                    ft.Text(f"{ld['count']} ({pct:.1f}%)", size=11),
                ], spacing=8, vertical_alignment=ft.CrossAxisAlignment.CENTER)
            )

        stats_content.controls.append(ft.Divider(height=20))
        stats_content.controls.append(ft.Text("Padroes por Categoria", size=14, weight=ft.FontWeight.BOLD))

        cat_dist = db.get_category_distribution()
        total_pat = s["total_patterns"]
        for cd in cat_dist[:10]:
            pct = (cd["count"] / total_pat * 100) if total_pat > 0 else 0
            bar_color = _category_color(cd["category"])
            stats_content.controls.append(
                ft.Row([
                    ft.Text(cd["category"].upper(), size=11, width=80, color=bar_color, weight=ft.FontWeight.BOLD),
                    ft.Container(
                        ft.Container(width=max(pct * 2, 2), height=16, bgcolor=bar_color, border_radius=4),
                        expand=True,
                    ),
                    ft.Text(f"{cd['count']} ({pct:.1f}%)", size=11),
                ], spacing=8, vertical_alignment=ft.CrossAxisAlignment.CENTER)
            )

        stats_content.controls.append(ft.Divider(height=20))
        stats_content.controls.append(ft.Text("Historico Diario", size=14, weight=ft.FontWeight.BOLD))

        daily = db.get_daily_stats(limit=14)
        for d in daily:
            stats_content.controls.append(
                ft.Row([
                    ft.Text(d["date"], size=11, width=100),
                    ft.Text(f"Total: {d['total_lines']}", size=11, width=90),
                    ft.Text(f"Erros: {d['errors']}", size=11, color=ft.Colors.RED_300, width=90),
                    ft.Text(f"Anomalias: {d['anomalies']}", size=11, color=ft.Colors.PURPLE_300),
                ], spacing=10)
            )

        page.update()

    def clear_data(e):
        nonlocal current_file_id, selected_file_path
        db.clear_all()
        current_file_id = 0
        selected_file_path = ""
        refresh_all_tables()
        switch_tab(2)
        set_status("Dados limpos")

    def switch_tab(index: int):
        for i, btn in enumerate(selected_tab_buttons):
            btn.style.bgcolor = ft.Colors.BLUE_700 if i == index else ft.Colors.SURFACE
        content_logs.current.visible = (index == 0)
        content_patterns.current.visible = (index == 1)
        content_import.current.visible = (index == 2)
        content_anomalies.current.visible = (index == 3)
        content_stats.current.visible = (index == 4)
        if index == 1:
            refresh_pattern_table()
        elif index == 3:
            refresh_anomaly_table()
        elif index == 4:
            refresh_stats_view()
        page.update()

    selected_tab_buttons = []

    def _tab_btn(label: str, icon, index: int, on_switch) -> ft.Button:
        is_first = (index == 0)
        return ft.Button(
            label,
            icon=icon,
            style=ft.ButtonStyle(
                bgcolor=ft.Colors.BLUE_700 if is_first else ft.Colors.SURFACE,
                color=ft.Colors.WHITE,
                text_style=ft.TextStyle(size=12),
                padding=ft.padding.Padding(left=16, top=8, right=16, bottom=8),
            ),
            on_click=lambda e: _handle_tab_click(e, index, on_switch),
        )

    def _handle_tab_click(e, index: int, on_switch):
        for i, btn in enumerate(selected_tab_buttons):
            btn.style.bgcolor = ft.Colors.BLUE_700 if i == index else ft.Colors.SURFACE
        on_switch(index)

    tab_buttons = ft.Row([
        _tab_btn("Logs", ft.Icons.LIST_ALT, 0, switch_tab),
        _tab_btn("Padroes", ft.Icons.PATTERN, 1, switch_tab),
        _tab_btn("Importar", ft.Icons.UPLOAD_FILE, 2, switch_tab),
        _tab_btn("Anomalias", ft.Icons.WARNING_AMBER, 3, switch_tab),
        _tab_btn("Estatisticas", ft.Icons.BAR_CHART, 4, switch_tab),
    ], spacing=2)

    selected_tab_buttons = tab_buttons.controls

    logs_page = ft.Column([
        ft.Row([
            filter_level,
            filter_anomaly_only,
            filter_problems_only,
            search_field,
            ft.Container(expand=True),
            logs_count_text,
        ], spacing=10, vertical_alignment=ft.CrossAxisAlignment.CENTER),
        ft.Divider(height=4),
        ft.Row([log_table], expand=True, scroll=ft.ScrollMode.AUTO),
    ], expand=True, spacing=0, visible=True, ref=content_logs)

    patterns_page = ft.Column([
        ft.Row([ft.Container(expand=True), patterns_count_text], spacing=10),
        ft.Divider(height=4),
        ft.Row([pattern_table], expand=True, scroll=ft.ScrollMode.AUTO),
    ], expand=True, spacing=0, visible=False, ref=content_patterns)

    import_page = ft.Column([_build_import_view(import_file, page)],
                            alignment=ft.MainAxisAlignment.CENTER,
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                            expand=True, visible=False, ref=content_import)

    anomalies_page = ft.Column([
        ft.Row([ft.Container(expand=True), anomalies_count_text], spacing=10),
        ft.Divider(height=4),
        ft.Row([anomaly_table], expand=True, scroll=ft.ScrollMode.AUTO),
    ], expand=True, spacing=0, visible=False, ref=content_anomalies)

    stats_page = ft.Column([stats_content], expand=True, scroll=ft.ScrollMode.AUTO,
                           visible=False, ref=content_stats)

    content_stack = ft.Stack([
        logs_page,
        patterns_page,
        import_page,
        anomalies_page,
        stats_page,
    ], expand=True, ref=content_areas)

    main_container = ft.Container(
        content=ft.Column([
            ft.Row([
                summary_stats,
                ft.Container(expand=True),
                ft.Column([
                    progress_bar,
                    progress_text,
                ], spacing=2, horizontal_alignment=ft.CrossAxisAlignment.END),
            ], spacing=10, vertical_alignment=ft.CrossAxisAlignment.START),
            ft.Divider(height=4),
            ft.Container(content=tab_buttons, padding=ft.padding.Padding(left=0, top=0, right=0, bottom=4)),
            ft.Divider(height=2),
            content_stack,
            ft.Divider(height=4),
            ft.Row([
                status_text,
                ft.Container(expand=True),
                ft.TextButton(
                    "Limpar Dados", icon=ft.Icons.DELETE, on_click=clear_data,
                    style=ft.ButtonStyle(color=ft.Colors.RED_300, text_style=ft.TextStyle(size=11)),
                ),
            ], spacing=10),
        ], expand=True, spacing=0),
        padding=ft.padding.Padding(left=12, top=12, right=12, bottom=12),
        expand=True,
    )
    page.add(main_container)
    set_status("Pronto. Importe um ficheiro de log para comecar.")

    any_data = db.get_stats_summary()
    if any_data["total_entries"] > 0:
        refresh_all_tables()
    else:
        switch_tab(2)


LOG_EXTENSIONS = (".log", ".txt", ".out", ".err", ".trace", ".dump", ".csv")

WINDOWS_LOG_NAMES = [
    ("System", "System"),
    ("Application", "Application"),
    ("Security", "Security"),
    ("Setup", "Setup"),
    ("Windows PowerShell", "Windows PowerShell"),
    ("Forwarded Events", "ForwardedEvents"),
]


def _fetch_windows_events(log_name: str, max_events: int = 500) -> str:
    ps_cmd = (
        f'Get-WinEvent -LogName "{log_name}" -MaxEvents {max_events} -ErrorAction SilentlyContinue | '
        'ForEach-Object { '
        '$ts = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"); '
        '$lvl = @{1="CRITICAL";2="ERROR";3="WARNING";4="INFO";5="INFO"}[$_.Level]; '
        'if (-not $lvl) { $lvl = "INFO" }; '
        '$prov = $_.ProviderName; '
        '$eid = $_.Id; '
        '$msg = $_.Message -replace "\\r?\\n", " | " -replace "\\s+", " "; '
        'if ($msg.Length -gt 800) { $msg = $msg.Substring(0, 800) + "..." }; '
        '"$ts [$lvl] [$prov] EventID=$eid; $msg" '
        '}'
    )
    try:
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', ps_cmd],
            capture_output=True, text=True, timeout=120,
        )
        return result.stdout.strip()
    except Exception:
        return ""


def _scan_directory(path: str) -> list[str]:
    found = []
    if not os.path.isdir(path):
        return found
    try:
        for root, _dirs, files in os.walk(path):
            if len(found) >= 200:
                break
            for f in files:
                if f.lower().endswith(LOG_EXTENSIONS):
                    full = os.path.join(root, f)
                    try:
                        if os.path.getsize(full) > 0:
                            found.append(full)
                    except OSError:
                        pass
    except PermissionError:
        pass
    return found


def _native_file_dialog() -> str:
    ps_cmd = (
        'Add-Type -AssemblyName System.Windows.Forms; '
        '$fd = New-Object System.Windows.Forms.OpenFileDialog; '
        "$fd.Filter = 'Log files (*.log;*.txt;*.out;*.err;*.trace;*.dump;*.csv)|*.log;*.txt;*.out;*.err;*.trace;*.dump;*.csv|All files (*.*)|*.*'; "
        "if ($fd.ShowDialog() -eq 'OK') { $fd.FileName }"
    )
    try:
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', ps_cmd],
            capture_output=True, text=True, timeout=120,
        )
        path = result.stdout.strip()
        return path if path and os.path.exists(path) else ""
    except Exception:
        return ""


def _native_folder_dialog() -> str:
    ps_cmd = (
        'Add-Type -AssemblyName System.Windows.Forms; '
        '$fd = New-Object System.Windows.Forms.FolderBrowserDialog; '
        "$fd.Description = 'Selecionar pasta para scan de logs'; "
        "if ($fd.ShowDialog() -eq 'OK') { $fd.SelectedPath }"
    )
    try:
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', ps_cmd],
            capture_output=True, text=True, timeout=120,
        )
        path = result.stdout.strip()
        return path if path and os.path.isdir(path) else ""
    except Exception:
        return ""


def _build_import_view(import_handler, page_ref) -> ft.Container:
    path_field = ft.TextField(
        width=450, height=44, text_size=14,
        hint_text="C:\\caminho\\para\\ficheiro.log",
        prefix_icon=ft.Icons.FILE_OPEN,
        dense=True,
    )

    scan_dir_field = ft.TextField(
        width=350, height=44, text_size=14,
        hint_text="C:\\pasta\\para\\fazer\\scan",
        prefix_icon=ft.Icons.FOLDER_OPEN,
        dense=True,
    )

    status = ft.Text("", size=11, color=ft.Colors.GREY_400)
    scan_status = ft.Text("", size=11, color=ft.Colors.GREY_400)

    win_status = ft.Text("", size=11, color=ft.Colors.GREY_400)
    win_count_field = ft.TextField(
        width=80, height=36, text_size=12, dense=True,
        value="500",
        keyboard_type=ft.KeyboardType.NUMBER,
    )
    win_log_dropdown = ft.Dropdown(
        width=200, height=36, text_size=12, dense=True,
        hint_text="Log do Windows",
        options=[ft.dropdown.Option(val, label) for label, val in WINDOWS_LOG_NAMES],
        value="System",
    )

    found_files_list = ft.ListView(spacing=4, height=180, expand=False)
    scan_result_container = ft.Container(
        content=ft.Column([
            ft.Text("Ficheiros encontrados:", size=12, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_300),
            found_files_list,
        ], spacing=8),
        visible=False,
        border=ft.border.Border(
            top=ft.border.BorderSide(1, ft.Colors.GREY_800),
            bottom=ft.border.BorderSide(1, ft.Colors.GREY_800),
            left=ft.border.BorderSide(1, ft.Colors.GREY_800),
            right=ft.border.BorderSide(1, ft.Colors.GREY_800),
        ),
        border_radius=8,
        padding=12,
        bgcolor=ft.Colors.BLACK12,
    )

    def on_browse_file(_):
        def _browse():
            path = _native_file_dialog()
            if path:
                path_field.value = path
                path_field.update()
                do_import_path(path)
        threading.Thread(target=_browse, daemon=True).start()

    def on_browse_folder(_):
        def _browse():
            path = _native_folder_dialog()
            if path:
                scan_dir_field.value = path
                scan_dir_field.update()
                do_scan(path)
        threading.Thread(target=_browse, daemon=True).start()

    def do_import(_):
        path = path_field.value.strip()
        if not path:
            status.value = "Escreva o caminho do ficheiro"
            status.color = ft.Colors.ORANGE_300
            path_field.update()
            status.update()
            return
        do_import_path(path)

    def do_import_path(path: str):
        if not os.path.exists(path):
            status.value = "Ficheiro nao encontrado"
            status.color = ft.Colors.RED_300
            path_field.update()
            status.update()
            return
        status.value = ""
        path_field.update()
        status.update()
        import_handler(path)
        path_field.value = ""

    path_field.on_submit = do_import

    def do_scan_click(_):
        path = scan_dir_field.value.strip() or os.getcwd()
        scan_dir_field.value = path
        scan_dir_field.update()
        do_scan(path)

    def do_scan(path: str):
        if not os.path.isdir(path):
            scan_status.value = "Diretorio invalido"
            scan_status.color = ft.Colors.RED_300
            scan_status.update()
            return

        scan_status.value = "A procurar ficheiros de log..."
        scan_status.color = ft.Colors.BLUE_200
        scan_status.update()
        scan_result_container.visible = True
        scan_result_container.update()

        def _scan_thread():
            found = _scan_directory(path)
            page_ref.run_task(_update_scan_results, found)

        threading.Thread(target=_scan_thread, daemon=True).start()

    async def _update_scan_results(found: list[str]):
        found_files_list.controls.clear()
        if not found:
            found_files_list.controls.append(
                ft.Text("Nenhum ficheiro de log encontrado.", size=12, color=ft.Colors.GREY_400)
            )
            scan_status.value = "Nenhum ficheiro encontrado"
            scan_status.color = ft.Colors.ORANGE_300
        else:
            for fpath in found:
                fname = os.path.basename(fpath)
                fsize = os.path.getsize(fpath)
                size_str = f"{fsize / 1024:.1f} KB" if fsize < 1024 * 1024 else f"{fsize / 1024 / 1024:.1f} MB"

                row = ft.Row([
                    ft.Icon(ft.Icons.DESCRIPTION, size=16, color=ft.Colors.BLUE_300),
                    ft.Text(fname, size=12, width=260, max_lines=1, overflow=ft.TextOverflow.ELLIPSIS,
                            tooltip=fpath),
                    ft.Text(size_str, size=11, color=ft.Colors.GREY_400, width=70),
                    ft.TextButton("Importar", icon=ft.Icons.UPLOAD_FILE,
                                   data=fpath,
                                   on_click=lambda e: do_import_path(e.control.data),
                                   style=ft.ButtonStyle(text_style=ft.TextStyle(size=11))),
                ], spacing=6, vertical_alignment=ft.CrossAxisAlignment.CENTER)
                found_files_list.controls.append(row)

            scan_status.value = f"Encontrados {len(found)} ficheiro(s)"
            scan_status.color = ft.Colors.GREEN_300

        scan_status.update()
        scan_result_container.update()

    def do_analyze_windows(_):
        log_name = win_log_dropdown.value
        if not log_name:
            win_status.value = "Seleciona um log do Windows"
            win_status.color = ft.Colors.ORANGE_300
            win_status.update()
            return

        try:
            max_events = int(win_count_field.value)
        except ValueError:
            max_events = 500

        if max_events < 1 or max_events > 2000:
            win_status.value = "Maximo entre 1 e 2000 eventos"
            win_status.color = ft.Colors.ORANGE_300
            win_status.update()
            return

        win_status.value = f"A obter {max_events} eventos do log '{log_name}'..."
        win_status.color = ft.Colors.BLUE_200
        win_status.update()

        def _fetch_thread():
            output = _fetch_windows_events(log_name, max_events)
            if not output.strip():
                page_ref.run_task(_win_fetch_done, log_name, 0, True)
                return

            lines = output.strip().split("\n")
            line_count = len(lines)

            tmp_path = os.path.join(tempfile.gettempdir(), f"windows_{log_name.lower().replace(' ', '_')}.log")
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(output)

            import_handler(tmp_path)
            page_ref.run_task(_win_fetch_done, log_name, line_count, False)

        threading.Thread(target=_fetch_thread, daemon=True).start()

    async def _win_fetch_done(log_name: str, count: int, is_error: bool):
        if is_error:
            win_status.value = f"Nenhum evento encontrado no log '{log_name}' (precisa Admin?)"
            win_status.color = ft.Colors.ORANGE_300
        else:
            win_status.value = f"Obtidos {count} eventos do log '{log_name}'"
            win_status.color = ft.Colors.GREEN_300
        win_status.update()

    return ft.Container(
        content=ft.Column([
            ft.Icon(ft.Icons.CLOUD_UPLOAD, size=48, color=ft.Colors.BLUE_300),
            ft.Text("Importar Ficheiro de Log", size=18, weight=ft.FontWeight.BOLD),

            ft.Divider(height=8),

            ft.Text("Importar ficheiro especifico", size=13, weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE_200),
            ft.Row([
                path_field,
                ft.Button("Procurar", icon=ft.Icons.FOLDER_OPEN,
                          on_click=on_browse_file),
                ft.Button("Importar", icon=ft.Icons.UPLOAD_FILE, on_click=do_import),
            ], spacing=10, alignment=ft.MainAxisAlignment.CENTER),
            status,

            ft.Divider(height=12),

            ft.Text("Scan automatico de diretorio", size=13, weight=ft.FontWeight.BOLD, color=ft.Colors.GREEN_200),
            ft.Text("Procura recursivamente por ficheiros de log (.log, .txt, .out, etc.)",
                    size=11, color=ft.Colors.GREY_400),
            ft.Row([
                scan_dir_field,
                ft.Button("Procurar Pasta", icon=ft.Icons.FOLDER_OPEN,
                          on_click=on_browse_folder),
                ft.Button("Scan", icon=ft.Icons.SEARCH, on_click=do_scan_click),
            ], spacing=10, alignment=ft.MainAxisAlignment.CENTER),
            scan_status,

            scan_result_container,

            ft.Divider(height=12),

            ft.Text("Logs do Windows (Event Viewer)", size=13, weight=ft.FontWeight.BOLD, color=ft.Colors.PURPLE_200),
            ft.Text("Obtem eventos diretamente do Event Log do Windows e analisa automaticamente",
                    size=11, color=ft.Colors.GREY_400),
            ft.Row([
                win_log_dropdown,
                ft.Text("Max:", size=12, color=ft.Colors.GREY_400),
                win_count_field,
                ft.Button("Analisar Logs do Windows", icon=ft.Icons.COMPUTER,
                          on_click=do_analyze_windows),
            ], spacing=10, alignment=ft.MainAxisAlignment.CENTER),
            win_status,

            ft.Text("Formatos suportados: syslog, JSON, texto, Apache/Nginx, CSV",
                    size=10, color=ft.Colors.GREY_600),
        ], alignment=ft.MainAxisAlignment.CENTER, spacing=8,
           horizontal_alignment=ft.CrossAxisAlignment.CENTER),
        border=ft.border.Border(
            top=ft.border.BorderSide(width=2, color=ft.Colors.BLUE_700),
            bottom=ft.border.BorderSide(width=2, color=ft.Colors.BLUE_700),
            left=ft.border.BorderSide(width=2, color=ft.Colors.BLUE_700),
            right=ft.border.BorderSide(width=2, color=ft.Colors.BLUE_700),
        ),
        border_radius=12,
        padding=ft.padding.Padding(left=30, top=20, right=30, bottom=20),
        bgcolor=ft.Colors.SURFACE,
    )


if __name__ == "__main__":
    ft.run(main)
