"""Shared KagNode identity; trusted SVG stays local to the application."""
from urllib.parse import quote

NAME = 'KagNode VPN'
PROJECT = 'KagNode Open source VPN server'
BLUE = '#2563eb'

# Two paths faithfully redrawn from the supplied logo reference. No background,
# scripts, remote fonts or linked assets are needed by the dashboard or portal.
MARK_PATHS = (
    'M107 6C55 1 5 20 5 73C5 109 24 129 81 124Z',
    'M117 38L139 65L123 119L102 104Z',
)
MARK_SVG = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 144 128" '
            'fill="' + BLUE + '" aria-hidden="true" focusable="false">' +
            ''.join('<path d="' + path + '"/>' for path in MARK_PATHS) + '</svg>')
FAVICON_URI = 'data:image/svg+xml,' + quote(MARK_SVG, safe='')


def wordmark_svg():
    """Transparent standalone wordmark with light/dark text for documentation."""
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 550 128" '
            'role="img" aria-labelledby="title"><title>' + NAME + '</title>'
            '<style>text{fill:#101114}@media(prefers-color-scheme:dark){text{fill:#f8fafc}}</style>'
            '<g fill="' + BLUE + '">' +
            ''.join('<path d="' + path + '"/>' for path in MARK_PATHS) + '</g>'
            '<text x="167" y="84" font-family="system-ui,-apple-system,sans-serif" '
            'font-size="51" font-weight="700" letter-spacing="-1">' + NAME + '</text></svg>')
