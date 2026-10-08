"""Device-free Cargo cache regression using the production build script."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RevisionBuildTest(unittest.TestCase):
    def test_revision_cache_worktree_overrides_and_archive(self):
        with tempfile.TemporaryDirectory(prefix="adb-revision-") as tmp:
            repo = Path(tmp) / "repo"
            crate = repo / "crates/adb-fastboot-cli"
            (crate / "src").mkdir(parents=True)
            (repo / "Cargo.toml").write_text('[workspace]\nmembers=["crates/adb-fastboot-cli"]\nresolver="2"\n')
            (crate / "Cargo.toml").write_text('[package]\nname="revision-probe"\nversion="0.1.0"\nedition="2021"\n')
            script = ROOT / "crates/adb-fastboot-cli/build.rs"
            if script.exists():
                shutil.copyfile(script, crate / "build.rs")
            source = (ROOT / "crates/adb-fastboot-cli/src/main_adb.rs").read_text()
            function = source[source.index('fn build_revision()'):source.index('\n/// The only compression')]
            (crate / "src/main.rs").write_text(function + '\nfn main() { println!("Revision {}-android", build_revision()); }\n')
            env = dict(os.environ)
            for key in ("ADB_RS_BUILD_REVISION", "GIT_REVISION", "CARGO_BUILD_BUILD_DIR"):
                env.pop(key, None)
            env["CARGO_TARGET_DIR"] = str(Path(tmp) / "target")

            def run(args, cwd=repo):
                return subprocess.check_output(args, cwd=cwd, env=env, text=True).strip()

            def revision(cwd=repo):
                env['CARGO_TARGET_DIR'] = str(Path(tmp) / ('target-' + cwd.name))
                value = run(['cargo', 'run', '--offline', '--quiet'], cwd)
                print(value, flush=True)
                return value

            run(['git', 'init', '-q'])
            run(['git', 'add', '.'])
            run(['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.com', 'commit', '-qm', 'initial'])
            expected = lambda cwd=repo: 'Revision ' + run(['git', 'rev-parse', 'HEAD'], cwd)[:12] + '-android'
            self.assertEqual(revision(), expected())
            run(['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.com', 'commit', '--allow-empty', '-qm', 'advance'])
            self.assertEqual(revision(), expected())
            run(['git', 'pack-refs', '--all', '--prune'])
            self.assertEqual(revision(), expected())
            tree = Path(tmp) / 'worktree'
            run(['git', 'worktree', 'add', '-q', '--detach', str(tree), 'HEAD~1'])
            self.assertEqual(revision(tree), expected(tree))
            run(['git', 'checkout', '-q', '--detach', 'HEAD~1'])
            self.assertEqual(revision(), expected())
            env['GIT_REVISION'] = 'alias'
            self.assertEqual(revision(), 'Revision alias-android')
            env['ADB_RS_BUILD_REVISION'] = ' explicit '
            self.assertEqual(revision(), 'Revision explicit-android')
            env['ADB_RS_BUILD_REVISION'] = ' '
            self.assertEqual(revision(), 'Revision alias-android')
            env.pop('ADB_RS_BUILD_REVISION')
            env.pop('GIT_REVISION')
            self.assertEqual(revision(), expected())
            archive = Path(tmp) / 'archive'
            shutil.copytree(repo, archive, ignore=shutil.ignore_patterns('.git'))
            self.assertEqual(revision(archive), 'Revision 0.1.0-android')


if __name__ == '__main__':
    unittest.main()
