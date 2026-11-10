"""The Scope stage: which source files a scan covers."""

import fnmatch
import os
from pathlib import Path, PurePosixPath

from .util import SolauditError, git


def git_root(root):
    proc = git(root, "rev-parse", "--show-toplevel", check=False)
    if proc.returncode != 0:
        raise SolauditError(f"not a git repository: {root}")
    return Path(proc.stdout.strip())


def default_base(root):
    """The remote's default branch: origin/HEAD, or the first conventional branch that exists."""
    proc = git(root, "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD", check=False)
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip()
    for ref in ("origin/main", "origin/master", "main", "master"):
        if git(root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}", check=False).returncode == 0:
            return ref
    raise SolauditError("unknown base: the remote has no default branch; pass --diff <base> or set `base`")


def resolve_base(root, base):
    """The commit the diff is taken from: the merge base of the base ref and HEAD."""
    if git(root, "rev-parse", "--verify", "--quiet", f"{base}^{{commit}}", check=False).returncode != 0:
        raise SolauditError(f"unknown base: {base} does not resolve to a commit")
    proc = git(root, "merge-base", base, "HEAD", check=False)
    if proc.returncode != 0:
        raise SolauditError(f"unknown base: {base} has no merge base with HEAD")
    return proc.stdout.strip()


def normalize_dir(directory):
    """A project-relative directory without `./`, `..` detours, or slashes at either end."""
    return PurePosixPath(os.path.normpath(str(directory).replace("\\", "/"))).as_posix().strip("/") or "."


def under(path, directory):
    directory = normalize_dir(directory)
    return directory in ("", ".") or path == directory or path.startswith(directory + "/")


def source_files(root, src):
    """Every .sol file under the source directory, project-relative."""
    base = Path(root) / src
    if not base.is_dir():
        return []
    return sorted(PurePosixPath(p.relative_to(root)).as_posix() for p in base.rglob("*.sol") if p.is_file())


def changed_files(root, merge_base, src):
    """The .sol files under src that differ between the merge base and the working tree."""
    diff = git(root, "diff", "--name-only", "--no-renames", "--relative", "-z", merge_base, "--")
    untracked = git(root, "ls-files", "--others", "--exclude-standard", "-z")
    paths = set(filter(None, diff.stdout.split("\0"))) | set(filter(None, untracked.stdout.split("\0")))
    return sorted(
        p for p in paths
        if p.endswith(".sol") and under(p, src) and (Path(root) / p).is_file()
    )


def importers_closure(changed, imports, candidates):
    """The changed files plus every candidate file that transitively imports one of them, through
    any chain of imports, including files that are not candidates themselves."""
    importers = {}
    for path, deps in imports.items():
        for dep in deps:
            importers.setdefault(dep, set()).add(path)
    seen = set(changed)
    queue = list(changed)
    while queue:
        for importer in importers.get(queue.pop(), ()):
            if importer not in seen:
                seen.add(importer)
                queue.append(importer)
    return sorted(p for p in seen if p in candidates or p in changed)


def excluded(path, src, patterns):
    """Whether a path matches an `exclude` glob, given relative to src or to the project root."""
    src = normalize_dir(src)
    relative = path[len(src) + 1:] if src != "." and under(path, src) else path
    return any(fnmatch.fnmatch(relative, p) or fnmatch.fnmatch(path, p) for p in patterns)


def apply_excludes(paths, src, patterns):
    return [p for p in paths if not excluded(p, src, patterns)]
