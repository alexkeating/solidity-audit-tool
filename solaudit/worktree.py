"""Testing worktrees: one scratch copy of the project per Hunt or Prove session."""

import hashlib
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path, PurePosixPath

from .util import GIT_SAFE, SolauditError, git, log

# git commands that change the repository's worktree list run one at a time; copying files does not.
GIT_LOCK = threading.Lock()


class Worktree:
    """A git worktree of HEAD with the project's uncommitted changes, libraries, and build cache."""

    def __init__(self, project, path):
        self.project = project  # the scanned project
        self.path = Path(path)  # the worktree's top level
        self.root = self.path / project.prefix  # the project inside the worktree
        self.links = []
        self.snapshot = {}
        self.spoiled = False  # a session changed something outside test/solaudit/

    def create(self):
        project = self.project
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with GIT_LOCK:
            git(project.root, "worktree", "add", "--detach", "--quiet", self.path, project.uncommitted()[0])
        # The worktree's own git directory, read before any session runs. Later git commands name it
        # explicitly, so a `.git` file a session rewrote cannot point them at a config it wrote.
        self.git_dir = Path(git(self.path, "rev-parse", "--absolute-git-dir").stdout.strip())
        self._apply_changes()
        for lib in project.foundry["libs"]:
            target = self.owned(lib)
            if target is not None:  # an absolute or `..` library is used where it is, not linked
                self._link_libs(project.root / lib, target)
        self.restore_build(keep_failures=False)
        self.snapshot = self.status()
        return self

    def restore_build(self, keep_failures=True):
        """Give the worktree fresh copies of the project's out/ and cache/, so the first build is
        incremental and a check never runs against build outputs a session could have altered.

        Only the fuzz failures forge saved during the session are kept, for the check to replay."""
        project = self.project
        # A saved fuzz failure is only an input to the test function, which still bounds it, so it is
        # kept for the check to replay. A saved invariant failure is a sequence of calls, senders
        # included, that a session could hand-write to replay a call its handler could never make,
        # so it is removed wherever forge keeps it.
        invariant = self.owned(project.foundry["invariant_failures"])
        if invariant is not None and invariant.is_dir():
            shutil.rmtree(invariant)
        fuzz = project.foundry["fuzz_failures"]
        kept = {}
        saved = self.owned(fuzz)
        # A fuzz directory that is, or holds, a build directory would bring the session's build back.
        overlaps = any(d == fuzz or d.startswith(fuzz.rstrip("/") + "/") for d in build_dirs(project.foundry))
        if keep_failures and saved is not None and saved.is_dir() and not overlaps:
            kept[fuzz] = self.path.parent / f".{self.path.name}-fuzz-failures"
            shutil.rmtree(kept[fuzz], ignore_errors=True)
            shutil.move(str(saved), kept[fuzz])
        for name in build_dirs(project.foundry):
            source, target = project.root / name, self.owned(name)
            if target is None:
                continue  # outside the worktree (`../out`, an absolute path): not the worktree's to replace
            if target.is_file():  # owned() refuses symlinks, so this is a plain file or directory
                target.unlink()
            elif target.exists():
                shutil.rmtree(target)
            if source.is_dir():
                copy_tree(source, target)
        for relative, saved in kept.items():
            target = self.owned(relative)
            if target is None:
                shutil.rmtree(saved, ignore_errors=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.rmtree(target, ignore_errors=True)
            shutil.move(str(saved), target)

    def owned(self, relative):
        """The path in the worktree that a project-relative path names, or None when it leads out
        of the worktree (an absolute path, `..` past its top, a symlink on the way) or is the
        project directory itself, and so must not be touched."""
        if Path(relative).is_absolute():
            return None
        top = self.path.resolve()
        path = Path(os.path.normpath(self.root.resolve() / relative))
        if path == self.root.resolve() or top not in path.parents:
            return None
        step = top
        for part in path.relative_to(top).parts:
            step = step / part
            if step.is_symlink():
                return None
        return path

    def _apply_changes(self):
        """Bring over tracked changes (staged or not) and untracked files from the working tree."""
        _, patch, untracked = self.project.uncommitted()
        if patch.strip():
            apply = subprocess.run(
                ["git", *GIT_SAFE, "apply", "--binary", "--whitespace=nowarn"],
                cwd=self.path, input=patch, capture_output=True,
            )
            if apply.returncode != 0:
                raise SolauditError(
                    f"cannot apply uncommitted changes to a worktree: {apply.stderr.decode(errors='replace').strip()}"
                )
        for relative, (link, content, mode) in untracked.items():
            target = self.path / relative
            if target.exists() or target.is_symlink():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if link is not None:
                os.symlink(link, target)
            else:
                target.write_bytes(content)
                os.chmod(target, mode)

    def _link_libs(self, source, target):
        """Replace each library directory that is empty in the worktree with a link to the project's."""
        if not source.is_dir():
            return
        if target.is_symlink():
            return
        if not target.exists() or (target.is_dir() and not any(target.iterdir())):
            if target.exists():
                target.rmdir()
            target.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(source, target)
            self.links.append(target)
            return
        if target.is_dir():
            for child in sorted(source.iterdir()):
                if child.is_dir() and not child.is_symlink():
                    self._link_libs(child, target / child.name)

    def status(self):
        """Every changed, untracked, or ignored path outside test/solaudit/ and the build
        directories, with a content hash. Ignored files count: forge reads some (a `.env`)."""
        proc = git(
            self.path, f"--git-dir={self.git_dir}", f"--work-tree={self.path}", "-c", "core.attributesFile=/dev/null",
            "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=matching",
            "--ignore-submodules=all", "--no-renames", check=False,
        )
        if proc.returncode != 0:
            return None  # unknown, which never matches a snapshot
        prefix = self.project.prefix_posix
        # Claude Code keeps its own records under .claude/ in a session's working directory, and
        # forge reads nothing there; the build directories are replaced before every check.
        foundry = self.project.foundry
        skip = []
        for d in (self.project.probe_dir, *build_dirs(foundry), foundry["fuzz_failures"],
                  foundry["invariant_failures"], ".claude"):
            # git names paths from the repository's top, where the project may sit lower down.
            path = os.path.normpath(f"{prefix}{d}")
            if not path.startswith(".."):
                skip.append(PurePosixPath(path).as_posix() + "/")
        state = {}
        entries = proc.stdout.split("\0")
        i = 0
        while i < len(entries):
            entry = entries[i]
            i += 1
            if len(entry) < 4:
                continue
            code, path = entry[:2], entry[3:]
            if code[0] in "RC":
                i += 1  # the rename's source path follows
            if any(path.startswith(s) for s in skip):
                continue
            state[path] = (code, _digest(self.path / path))
        return state

    def changed_outside_probes(self):
        """Whether anything outside test/solaudit/ changed since the worktree was set up."""
        now = self.status()
        if now is None or self.snapshot is None or now != self.snapshot:
            self.spoiled = True
        return self.spoiled

    def remove(self):
        for link in self.links:
            try:
                link.unlink()
            except OSError:
                pass
        with GIT_LOCK:
            proc = git(self.project.root, "worktree", "remove", "--force", self.path, check=False)
            if proc.returncode != 0 and self.path.exists():
                shutil.rmtree(self.path, ignore_errors=True)
            git(self.project.root, "worktree", "prune", check=False)


def build_dirs(foundry):
    """The build output directories a worktree gets fresh copies of: out/, cache/, and a
    build-info directory outside out/."""
    dirs = [foundry["out"], foundry["cache_path"]]
    build_info = foundry.get("build_info")
    if build_info and not (build_info == foundry["out"] or build_info.startswith(foundry["out"].rstrip("/") + "/")):
        dirs.append(build_info)
    return dirs


def copy_tree(source, target):
    """Copy a build directory, as a copy-on-write clone where the filesystem allows (GNU cp)."""
    if sys.platform.startswith("linux") and shutil.which("cp"):
        proc = subprocess.run(["cp", "-a", "--reflink=auto", str(source), str(target)], capture_output=True)
        if proc.returncode == 0:
            return
        shutil.rmtree(target, ignore_errors=True)
    shutil.copytree(source, target, symlinks=True)


def _digest(path):
    try:
        if path.is_symlink():
            return "link:" + os.readlink(path)
        if path.is_file():
            return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        pass
    return None


def remove_all(worktrees):
    for worktree in worktrees:
        try:
            worktree.remove()
        except Exception as error:  # cleanup must not hide the scan's own outcome
            log(f"could not remove worktree {worktree.path}: {error}")
