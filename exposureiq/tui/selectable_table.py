"""Text selection for the pinned Textual 8 DataTable, which disables it by default."""

from itertools import chain

from rich.segment import Segment
from rich.style import Style
from rich.text import Text
from textual import events
from textual._segment_tools import line_crop
from textual.selection import Selection
from textual.strip import Strip
from textual.widgets import DataTable


class SelectableDataTable(DataTable):
    """Keep table navigation, but expose rendered characters to screen selection."""

    ALLOW_SELECT = True

    def _copy_row_text(self, row_index: int) -> str:
        values = self.get_row_at(row_index)
        # Host names may appear in a different column (e.g. Findings), and IP
        # rows have no single host. Never copy status, severity, or a whole row.
        for label in ("Subdomain", "Host", "Domain", "Hosts", "IP"):
            for column, value in zip(self.ordered_columns, values):
                if column.label.plain == label:
                    text = value.plain if isinstance(value, Text) else str(value)
                    return (text.split(",", 1)[0] if label == "Hosts" else text).strip()
        return ""

    def _on_click(self, event: events.Click) -> None:
        if event.chain < 2:
            return  # Textual will run the inherited single-click/navigation handler.
        # The inherited Widget handler selects the entire table on double-click
        # (or its container on triple-click). Stop both, even on empty/header rows.
        event.prevent_default()
        event.stop()
        if self.text_selection is not None:
            return  # A repeated drag can also produce a chained Click; keep its exact selection.
        self.screen.clear_selection()
        row_index = event.style.meta.get("row")
        if (event.button == 1 and event.chain == 2 and isinstance(row_index, int)
                and 0 <= row_index < self.row_count):
            self.move_cursor(row=row_index, scroll=False)
            text = self._copy_row_text(row_index)
            if text:
                self.app.copy_to_clipboard(text)

    def _row_lines(self, y: int):
        row_key, line_no = self._get_offsets(y)
        return self._render_line_in_row(
            row_key, line_no, self.rich_style,
            cursor_location=self.cursor_coordinate, hover_location=self.hover_coordinate,
        )

    def _mark_characters(self, segments, y: int, x: int = 0, split: bool = False):
        selection = self.text_selection
        span = selection.get_span(y) if selection else None
        for segment in segments:
            if segment.control:
                yield segment
                continue
            if not split and not span:
                style = (segment.style or Style.null()) + Style.from_meta({"offset": (x, y)})
                yield Segment(segment.text, style)
                x += len(segment.text)
                continue
            for character in segment.text:
                style = (segment.style or Style.null()) + Style.from_meta({"offset": (x, y)})
                if span and x >= span[0] and (span[1] == -1 or x < span[1]):
                    style += self.selection_style
                yield Segment(character, style)
                x += 1

    def _render_line(self, y: int, x1: int, x2: int, base_style: Style) -> Strip:
        # Attach offsets before cropping, so dragging still selects the right
        # characters after scrolling, including characters wider than one cell.
        key = ("selection", y, x1, x2, self.size.width, self.cursor_coordinate,
               self.hover_coordinate, base_style, self.cursor_type, self._show_hover_cursor,
               self._update_count, self._pseudo_class_state, self.text_selection)
        if key in self._line_cache:
            return self._line_cache[key]
        try:
            fixed, scrollable = self._row_lines(y)
        except LookupError:
            return Strip.blank(self.size.width, base_style)
        label = fixed[0] if self._labelled_row_exists and self.show_row_labels else []
        label_length = sum(len(segment.text) for segment in label)
        fixed_segments = list(self._mark_characters(chain.from_iterable(fixed), y, split=bool(x1)))
        scroll_segments = list(self._mark_characters(chain.from_iterable(scrollable), y,
                                                     label_length, split=bool(x1)))
        fixed_width = sum(column.get_render_width(self)
                          for column in self.ordered_columns[:self.fixed_columns])
        segments = fixed_segments + line_crop(scroll_segments, x1 + fixed_width, x2, self.size.width)
        strip = Strip(segments).adjust_cell_length(self.size.width, base_style).simplify()
        self._line_cache[key] = strip
        return strip

    def get_selection(self, selection: Selection) -> tuple[str, str] | None:
        height = (self.header_height if self.show_header else 0) + sum(
            row.height for row in self.ordered_rows)
        start = selection.start.y if selection.start else 0
        end = selection.end.y if selection.end else height - 1
        lines = []
        for y in range(max(0, start), min(height - 1, end) + 1):
            fixed, scrollable = self._row_lines(y)
            label = fixed[0] if self._labelled_row_exists and self.show_row_labels else []
            text = "".join(segment.text for segment in chain(label, chain.from_iterable(scrollable)))
            span = selection.get_span(y)
            if span:
                lines.append(text[span[0]:None if span[1] == -1 else span[1]])
        return ("\n".join(lines), "\n") if lines else None
