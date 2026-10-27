"""Canonical SemVer comparison and Debian package version mapping."""
import re
PATTERN = r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(beta|rc)\.([1-9]\d*))?'
def parse(value):
    m = re.fullmatch(PATTERN, value)
    if not m:
        raise ValueError('Invalid VPN release version: ' + str(value))
    major, minor, patch, stage, number = m.groups()
    return (int(major), int(minor), int(patch), {None:2,'rc':1,'beta':0}[stage], int(number or 0))
def debian(value):
    parse(value)
    return value.replace('-', '~')
def eligible(value, prerelease=False):
    return parse(value)[3] == 2 or prerelease
