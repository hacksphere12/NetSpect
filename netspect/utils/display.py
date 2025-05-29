from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from typing import List, Dict, Any, Optional

console = Console()

def print_success(message: str):
    console.print(f"[bold green]✅ {message}[/bold green]")

def print_warning(message: str):
    console.print(f"[bold yellow]⚠️ {message}[/bold yellow]")

def print_error(message: str):
    console.print(f"[bold red]❌ {message}[/bold red]")

def print_info(message: str):
    console.print(f"[bold blue]ℹ️ {message}[/bold blue]")

def print_panel(content: str, title: Optional[str] = None, style: str = "cyan"):
    console.print(Panel(content, title=title, border_style=style, expand=False))

def create_table(title: Optional[str] = None, columns: Optional[List[str]] = None) -> Table:
    table = Table(title=title, show_header=True, header_style="bold magenta")
    if columns:
        for col in columns:
            table.add_column(col)
    return table

def display_table(data: List[Dict[str, Any]], title: Optional[str] = None, columns: Optional[List[str]] = None):
    if not data:
        print_warning("No data to display.")
        return

    if not columns:
        columns = list(data[0].keys())

    table = create_table(title=title, columns=columns)
    for row_data in data:
        table.add_row(*(str(row_data.get(col, "")) for col in columns))
    console.print(table)

def get_progress_bar() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=True # Clears progress bar on completion
)
