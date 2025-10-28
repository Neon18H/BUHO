from pathlib import Path

from app.parsers.gobuster import parse_gobuster
from app.parsers.nikto import parse_nikto
from app.parsers.sqlmap import parse_sqlmap
from app.parsers.wapiti import parse_wapiti

ROOT = Path(__file__).resolve().parents[2]
MOCKS = ROOT / 'scripts/mocks'


def test_parse_wapiti():
    results = list(parse_wapiti(MOCKS / 'wapiti.json'))
    assert results
    assert results[0]['tool'] == 'wapiti'


def test_parse_nikto():
    results = list(parse_nikto(MOCKS / 'nikto.json'))
    assert results
    assert results[0]['tool'] == 'nikto'


def test_parse_sqlmap():
    results = list(parse_sqlmap(MOCKS / 'sqlmap.json'))
    assert results
    assert results[0]['tool'] == 'sqlmap'


def test_parse_gobuster():
    results = list(parse_gobuster(MOCKS / 'gobuster.json'))
    assert results
    assert results[0]['tool'] == 'gobuster'
