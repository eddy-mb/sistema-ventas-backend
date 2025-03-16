from datetime import date, datetime, timedelta, timezone


def get_current_timestamp() -> datetime:
    """
    Obtiene la fecha y hora actual en UTC.

    Returns:
        Objeto datetime con la fecha y hora actual en UTC.
    """
    return datetime.now(timezone.utc)


def format_date(date: datetime, format_str: str = "%Y-%m-%d") -> str:
    """
    Formatea una fecha al formato especificado.

    Args:
        date: Fecha a formatear.
        format_str: Formato deseado (por defecto: YYYY-MM-DD).

    Returns:
        Cadena con la fecha formateada.
    """
    if not date:
        return ""
    return date.strftime(format_str)


def calculate_age(birth_date: datetime | date) -> int:
    """
    Calcula la edad en años a partir de la fecha de nacimiento.

    Args:
        birth_date: Fecha de nacimiento.

    Returns:
        Edad en años.
    """
    if not birth_date:
        return 0

    today = datetime.now(timezone.utc).date()

    # Si birth_date es datetime, convertirlo a date
    if isinstance(birth_date, datetime):
        birth_date = birth_date.date()

    age = today.year - birth_date.year

    # Restar un año si aún no ha pasado el cumpleaños este año
    if (today.month, today.day) < (birth_date.month, birth_date.day):
        age -= 1

    return age


def add_days_to_date(date: datetime, days: int) -> datetime:
    """
    Suma un número de días a una fecha.

    Args:
        date: Fecha base.
        days: Número de días a sumar (puede ser negativo para restar).

    Returns:
        Nueva fecha con los días sumados.
    """
    if not date:
        date = get_current_timestamp()

    return date + timedelta(days=days)


def truncate_string(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Trunca un texto a la longitud máxima especificada.

    Args:
        text: Texto a truncar.
        max_length: Longitud máxima.
        suffix: Sufijo a añadir si se trunca.

    Returns:
        Texto truncado.
    """
    if not text:
        return ""

    if len(text) <= max_length:
        return text

    return text[: max_length - len(suffix)] + suffix
