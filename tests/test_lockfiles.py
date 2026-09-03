"""
Direct unit tests for cli.parsers.lockfiles: the multi-ecosystem lockfile
parser (uv.lock, package-lock.json, go.sum, Gradle/Maven) that feeds a
SLSA v1.0 provenance predicate's `resolvedDependencies`. Covers each
parser's happy path, the module's own "Hardened against" fail-closed
guarantees (missing/corrupt/malformed input never raises, always []),
and detect_and_parse_dependencies()'s auto-detection + dedup behavior.
"""
import base64
import hashlib
import os
import shutil
import tempfile
import unittest

from cli.parsers.lockfiles import (
    ResolvedDependency,
    detect_and_parse_dependencies,
    parse_go_sum,
    parse_gradle_lockfile,
    parse_maven_pom_dependencies,
    parse_package_lock_json,
    parse_pip_compile_requirements,
    parse_pnpm_lock,
    parse_uv_lock,
)


def _sri(algo: str, raw_bytes: bytes) -> str:
    return f"{algo}-{base64.b64encode(raw_bytes).decode('ascii')}"


class TmpDirMixin:
    def _tmp(self) -> str:
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        return d

    def _write(self, name: str, content: str, tmp_dir: str = None) -> str:
        d = tmp_dir if tmp_dir is not None else self._tmp()
        path = os.path.join(d, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path


class ResolvedDependencyTests(unittest.TestCase):
    def test_to_dict(self):
        dep = ResolvedDependency(uri="pkg:pypi/pytest@8.3.2", digest={"sha256": "ab12"})
        self.assertEqual(dep.to_dict(), {"uri": "pkg:pypi/pytest@8.3.2", "digest": {"sha256": "ab12"}})

    def test_to_dict_default_empty_digest(self):
        dep = ResolvedDependency(uri="pkg:maven/org.foo/bar@1.0")
        self.assertEqual(dep.to_dict(), {"uri": "pkg:maven/org.foo/bar@1.0", "digest": {}})


class ParseUvLockTests(TmpDirMixin, unittest.TestCase):
    def test_wheel_hash(self):
        toml = """
version = 1
requires-python = ">=3.11"

[[package]]
name = "pytest"
version = "8.3.2"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://example/pytest-8.3.2-py3-none-any.whl", hash = "sha256:deadbeef" },
]
"""
        path = self._write("uv.lock", toml)
        deps = parse_uv_lock(path)
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0].uri, "pkg:pypi/pytest@8.3.2")
        self.assertEqual(deps[0].digest, {"sha256": "deadbeef"})

    def test_name_normalization(self):
        toml = """
[[package]]
name = "Django_REST.Framework"
version = "3.14.0"
source = { registry = "https://pypi.org/simple" }
"""
        path = self._write("uv.lock", toml)
        deps = parse_uv_lock(path)
        self.assertEqual(deps[0].uri, "pkg:pypi/django-rest-framework@3.14.0")

    def test_sdist_fallback_when_no_wheels(self):
        toml = """
[[package]]
name = "somepkg"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://example/somepkg-1.0.0.tar.gz", hash = "sha512:cafef00d" }
"""
        path = self._write("uv.lock", toml)
        deps = parse_uv_lock(path)
        self.assertEqual(deps[0].digest, {"sha512": "cafef00d"})

    def test_git_source_commit_fallback(self):
        toml = """
[[package]]
name = "mypkg"
version = "0.1.0"
source = { git = "https://github.com/org/repo?rev=deadbeef#1234567890abcdef1234567890abcdef12345678" }
"""
        path = self._write("uv.lock", toml)
        deps = parse_uv_lock(path)
        self.assertEqual(deps[0].digest, {"gitCommit": "1234567890abcdef1234567890abcdef12345678"})

    def test_no_hash_available_yields_empty_digest(self):
        toml = """
[[package]]
name = "mypkg"
version = "0.1.0"
source = { registry = "https://pypi.org/simple" }
"""
        path = self._write("uv.lock", toml)
        deps = parse_uv_lock(path)
        self.assertEqual(deps[0].digest, {})

    def test_missing_name_or_version_skipped(self):
        toml = """
[[package]]
version = "1.0.0"

[[package]]
name = "ok"
version = "2.0.0"
"""
        path = self._write("uv.lock", toml)
        deps = parse_uv_lock(path)
        self.assertEqual([d.uri for d in deps], ["pkg:pypi/ok@2.0.0"])

    def test_missing_file_returns_empty(self):
        self.assertEqual(parse_uv_lock(os.path.join(self._tmp(), "nope.lock")), [])

    def test_malformed_toml_returns_empty(self):
        path = self._write("uv.lock", "this is [ not valid toml =")
        self.assertEqual(parse_uv_lock(path), [])

    def test_empty_file_returns_empty(self):
        path = self._write("uv.lock", "")
        self.assertEqual(parse_uv_lock(path), [])

    def test_no_package_array_returns_empty(self):
        path = self._write("uv.lock", "version = 1\n")
        self.assertEqual(parse_uv_lock(path), [])

    def test_null_byte_path_returns_empty(self):
        self.assertEqual(parse_uv_lock("uv.lock\x00evil"), [])


class ParsePipCompileRequirementsTests(TmpDirMixin, unittest.TestCase):
    def test_single_requirement_with_hashes(self):
        content = (
            "#\n"
            "# This file is autogenerated by pip-compile\n"
            "#\n"
            "attrs==23.1.0 \\\n"
            "    --hash=sha256:1f28b4522cdc2fb4256ac1a020c78acf9cba2c6b461ccd2c126f3aa8e8335d1 \\\n"
            "    --hash=sha256:6279836d581513a26f1bf235f9acd333bc9115683f14f7e8fae46c98fc50e15\n"
            "    # via -r requirements.in\n"
        )
        path = self._write("requirements.txt", content)
        deps = parse_pip_compile_requirements(path)
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0].uri, "pkg:pypi/attrs@23.1.0")
        # Both --hash lines fold into the same digest dict, same algo key.
        self.assertEqual(
            deps[0].digest,
            {"sha256": "6279836d581513a26f1bf235f9acd333bc9115683f14f7e8fae46c98fc50e15"},
        )

    def test_multiple_requirements(self):
        content = (
            "attrs==23.1.0 \\\n"
            "    --hash=sha256:1f28b4522cdc2fb4256ac1a020c78acf9cba2c6b461ccd2c126f3aa8e8335d1\n"
            "certifi==2023.7.22 \\\n"
            "    --hash=sha256:92d6037539857d8206b8f6ae472e8b77db8058fec5937843c7af65f571a1546\n"
        )
        path = self._write("requirements.txt", content)
        deps = parse_pip_compile_requirements(path)
        self.assertEqual({d.uri for d in deps}, {"pkg:pypi/attrs@23.1.0", "pkg:pypi/certifi@2023.7.22"})

    def test_name_normalization(self):
        content = "Django_REST.Framework==3.14.0 \\\n    --hash=sha256:" + "a" * 64 + "\n"
        path = self._write("requirements.txt", content)
        deps = parse_pip_compile_requirements(path)
        self.assertEqual(deps[0].uri, "pkg:pypi/django-rest-framework@3.14.0")

    def test_plain_unhashed_requirements_txt_returns_empty(self):
        """The exact scenario this parser must never mistake for a real
        lockfile -- a hand-written requirements.txt with ordinary version
        pins and no --hash lines at all."""
        content = "requests==2.31.0\nflask>=2.0\n# a hand-written file\n"
        path = self._write("requirements.txt", content)
        self.assertEqual(parse_pip_compile_requirements(path), [])

    def test_requirement_with_no_hash_lines_is_skipped_individually(self):
        """A mixed file -- one real hash-pinned entry, one bare pin with
        no --hash lines (e.g. a local/editable install pip-compile can't
        hash) -- keeps the real one and drops only the unhashed one."""
        content = (
            "attrs==23.1.0 \\\n"
            "    --hash=sha256:" + "b" * 64 + "\n"
            "-e ./local-package\n"
            "certifi==2023.7.22 \\\n"
            "    --hash=sha256:" + "c" * 64 + "\n"
        )
        path = self._write("requirements.txt", content)
        deps = parse_pip_compile_requirements(path)
        self.assertEqual({d.uri for d in deps}, {"pkg:pypi/attrs@23.1.0", "pkg:pypi/certifi@2023.7.22"})

    def test_missing_file_returns_empty(self):
        self.assertEqual(parse_pip_compile_requirements("/nonexistent/requirements.txt"), [])

    def test_null_byte_path_returns_empty(self):
        self.assertEqual(parse_pip_compile_requirements("requirements.txt\x00evil"), [])


class ParsePackageLockJsonTests(TmpDirMixin, unittest.TestCase):
    def test_v3_packages_map(self):
        integrity = _sri("sha512", hashlib.sha512(b"lodash-content").digest())
        doc = {
            "name": "myapp",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "myapp", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.21", "integrity": integrity},
            },
        }
        import json

        path = self._write("package-lock.json", json.dumps(doc))
        deps = parse_package_lock_json(path)
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0].uri, "pkg:npm/lodash@4.17.21")
        expected_hex = hashlib.sha512(b"lodash-content").hexdigest()
        self.assertEqual(deps[0].digest, {"sha512": expected_hex})

    def test_scoped_package(self):
        import json

        doc = {"packages": {"node_modules/@babel/core": {"version": "7.18.0"}}}
        path = self._write("package-lock.json", json.dumps(doc))
        deps = parse_package_lock_json(path)
        self.assertEqual(deps[0].uri, "pkg:npm/%40babel/core@7.18.0")

    def test_nested_node_modules_uses_last_segment(self):
        import json

        doc = {"packages": {"node_modules/foo/node_modules/bar": {"version": "2.0.0"}}}
        path = self._write("package-lock.json", json.dumps(doc))
        deps = parse_package_lock_json(path)
        self.assertEqual(deps[0].uri, "pkg:npm/bar@2.0.0")

    def test_linked_workspace_entry_skipped(self):
        import json

        doc = {"packages": {"node_modules/workspace-pkg": {"version": "1.0.0", "link": True}}}
        path = self._write("package-lock.json", json.dumps(doc))
        self.assertEqual(parse_package_lock_json(path), [])

    def test_multi_hash_integrity_prefers_strongest(self):
        import json

        sha1_hex = hashlib.sha1(b"x").digest()
        sha512_hex = hashlib.sha512(b"y").digest()
        integrity = f"{_sri('sha1', sha1_hex)} {_sri('sha512', sha512_hex)}"
        doc = {"packages": {"node_modules/pkg": {"version": "1.0.0", "integrity": integrity}}}
        path = self._write("package-lock.json", json.dumps(doc))
        deps = parse_package_lock_json(path)
        self.assertEqual(deps[0].digest, {"sha512": sha512_hex.hex()})

    def test_malformed_sri_string_yields_empty_digest(self):
        import json

        doc = {"packages": {"node_modules/pkg": {"version": "1.0.0", "integrity": "sha512-not-valid-base64!!!"}}}
        path = self._write("package-lock.json", json.dumps(doc))
        deps = parse_package_lock_json(path)
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0].digest, {})

    def test_v1_lockfile_no_packages_key_returns_empty(self):
        import json

        doc = {"name": "myapp", "lockfileVersion": 1, "dependencies": {"lodash": {"version": "4.17.21"}}}
        path = self._write("package-lock.json", json.dumps(doc))
        self.assertEqual(parse_package_lock_json(path), [])

    def test_malformed_json_returns_empty(self):
        path = self._write("package-lock.json", "{not valid json")
        self.assertEqual(parse_package_lock_json(path), [])

    def test_missing_file_returns_empty(self):
        self.assertEqual(parse_package_lock_json(os.path.join(self._tmp(), "nope.json")), [])

    def test_missing_version_skipped(self):
        import json

        doc = {"packages": {"node_modules/pkg": {"integrity": "sha512-abc"}}}
        path = self._write("package-lock.json", json.dumps(doc))
        self.assertEqual(parse_package_lock_json(path), [])


class ParsePnpmLockTests(TmpDirMixin, unittest.TestCase):
    # Real excerpt from lockfileVersion 9.0's `packages:`/`snapshots:` split
    # schema, confirmed against a real, current lockfile
    # (github.com/pnpm/logger's own pnpm-lock.yaml) before writing the
    # parser -- not a hand-guessed shape.
    _V9_LOCK = """lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      bole:
        specifier: ^5.0.0
        version: 5.0.14

packages:

  '@babel/code-frame@7.24.7':
    resolution: {integrity: sha512-BcYH1CVJBO9tvyIZ2jVeXgSIMvGZ2FDRvDdOIVQyuklNKSsx+eppDEBq/g47Ayw+RqNFE+URvOShmf+f/qwAlA==}
    engines: {node: '>=6.9.0'}

  ts-node@10.9.2:
    resolution: {integrity: sha512-f0FFpIdcHgn8zcPSbf1dRevwt047YMnaiJM3u2w2RewrB+fob/zePZcrOyQoLMMO7aBIddLcQIEK5dYjkLnGrQ==}
    hasBin: true

snapshots:

  '@babel/code-frame@7.24.7':
    dependencies:
      '@babel/highlight': 7.24.7
      picocolors: 1.0.1

  ts-node@10.9.2(@types/node@18.19.43)(typescript@4.9.5):
    dependencies:
      '@types/node': 18.19.43
      typescript: 4.9.5
    transitivePeerDependencies:
      - '@swc/core'
      - '@swc/wasm'
"""

    def test_v9_scoped_and_unscoped_packages(self):
        path = self._write("pnpm-lock.yaml", self._V9_LOCK)
        deps = {d.uri: d for d in parse_pnpm_lock(path)}
        self.assertEqual(set(deps), {"pkg:npm/%40babel/code-frame@7.24.7", "pkg:npm/ts-node@10.9.2"})

    def test_v9_integrity_decoded_from_resolution(self):
        path = self._write("pnpm-lock.yaml", self._V9_LOCK)
        deps = {d.uri: d for d in parse_pnpm_lock(path)}
        expected_hex = base64.b64decode(
            "BcYH1CVJBO9tvyIZ2jVeXgSIMvGZ2FDRvDdOIVQyuklNKSsx+eppDEBq/g47Ayw+RqNFE+URvOShmf+f/qwAlA=="
        ).hex()
        self.assertEqual(deps["pkg:npm/%40babel/code-frame@7.24.7"].digest, {"sha512": expected_hex})

    def test_snapshots_block_is_not_scanned_for_packages(self):
        """The snapshots: block's own peer-suffixed keys
        (ts-node@10.9.2(@types/node@...)(typescript@...)) must never be
        treated as a second, separate package -- only the bare-version
        packages: entry should surface."""
        path = self._write("pnpm-lock.yaml", self._V9_LOCK)
        deps = parse_pnpm_lock(path)
        self.assertEqual(len([d for d in deps if d.uri.startswith("pkg:npm/ts-node@")]), 1)

    def test_pre_v9_leading_slash_key_format(self):
        """lockfileVersion 6.0 and earlier: a single packages: block, no
        snapshots: split, keys are registry-relative ("/name@version")
        rather than bare -- per pnpm's own spec
        (github.com/pnpm/spec/blob/master/lockfile/6.0.md)."""
        lock = """lockfileVersion: '6.0'

packages:

  /lodash@4.17.21:
    resolution: {integrity: sha512-v2kDEe57lecTulaDIuNTPy3Ry4/GaHuTHmpNjCf7VcMFwKvfW+9CY9nUsQ2h2QazgHbNCJ3IZndZWFj5cIiu6A==}
    dev: false
"""
        path = self._write("pnpm-lock.yaml", lock)
        deps = parse_pnpm_lock(path)
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0].uri, "pkg:npm/lodash@4.17.21")
        self.assertTrue(deps[0].digest.get("sha512"))

    def test_scoped_leading_slash_key(self):
        lock = """lockfileVersion: '6.0'

packages:

  /@babel/code-frame@7.24.7:
    resolution: {integrity: sha512-BcYH1CVJBO9tvyIZ2jVeXgSIMvGZ2FDRvDdOIVQyuklNKSsx+eppDEBq/g47Ayw+RqNFE+URvOShmf+f/qwAlA==}
"""
        path = self._write("pnpm-lock.yaml", lock)
        deps = parse_pnpm_lock(path)
        self.assertEqual(deps[0].uri, "pkg:npm/%40babel/code-frame@7.24.7")

    def test_entry_with_no_resolution_line_gets_empty_digest(self):
        lock = """lockfileVersion: '9.0'

packages:

  weird-package@1.0.0:
    engines: {node: '>=6.9.0'}
"""
        path = self._write("pnpm-lock.yaml", lock)
        deps = parse_pnpm_lock(path)
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0].digest, {})

    def test_no_packages_block_returns_empty(self):
        lock = "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies: {}\n"
        path = self._write("pnpm-lock.yaml", lock)
        self.assertEqual(parse_pnpm_lock(path), [])

    def test_missing_file_returns_empty(self):
        self.assertEqual(parse_pnpm_lock("/nonexistent/pnpm-lock.yaml"), [])

    def test_null_byte_path_returns_empty(self):
        self.assertEqual(parse_pnpm_lock("pnpm-lock.yaml\x00evil"), [])


class ParseGoSumTests(TmpDirMixin, unittest.TestCase):
    def test_module_and_gomod_lines(self):
        content = hashlib.sha256(b"gin-content").digest()
        h1 = base64.b64encode(content).decode("ascii")
        gomod_h1 = base64.b64encode(hashlib.sha256(b"gomod-only").digest()).decode("ascii")
        text = (
            f"github.com/gin-gonic/gin v1.9.1 h1:{h1}\n"
            f"github.com/gin-gonic/gin v1.9.1/go.mod h1:{gomod_h1}\n"
        )
        path = self._write("go.sum", text)
        deps = parse_go_sum(path)
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0].uri, "pkg:golang/github.com/gin-gonic/gin@v1.9.1")
        self.assertEqual(deps[0].digest, {"sha256": content.hex()})

    def test_malformed_hash_yields_empty_digest_not_dropped(self):
        text = "github.com/foo/bar v1.0.0 h1:not-valid-base64!!!\n"
        path = self._write("go.sum", text)
        deps = parse_go_sum(path)
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0].digest, {})

    def test_blank_lines_and_unparseable_lines_skipped(self):
        text = "\n   \nnot a valid go.sum line\n"
        path = self._write("go.sum", text)
        self.assertEqual(parse_go_sum(path), [])

    def test_missing_file_returns_empty(self):
        self.assertEqual(parse_go_sum(os.path.join(self._tmp(), "nope.sum")), [])

    def test_empty_file_returns_empty(self):
        path = self._write("go.sum", "")
        self.assertEqual(parse_go_sum(path), [])


class ParseGradleLockfileTests(TmpDirMixin, unittest.TestCase):
    def test_standard_lockfile(self):
        text = (
            "# This is a Gradle generated file for dependency locking.\n"
            "# Manual edits can break the build and are not supported.\n"
            "#\n"
            "com.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath\n"
            "org.springframework.boot:spring-boot-starter:3.2.0=compileClasspath\n"
            "empty=annotationProcessor\n"
        )
        path = self._write("gradle.lockfile", text)
        deps = parse_gradle_lockfile(path)
        self.assertEqual(
            [d.uri for d in deps],
            [
                "pkg:maven/com.google.guava/guava@31.1-jre",
                "pkg:maven/org.springframework.boot/spring-boot-starter@3.2.0",
            ],
        )
        self.assertTrue(all(d.digest == {} for d in deps))

    def test_malformed_lines_skipped(self):
        text = "not-a-valid-line\ngroup:artifact-no-version=\n"
        path = self._write("gradle.lockfile", text)
        self.assertEqual(parse_gradle_lockfile(path), [])

    def test_missing_file_returns_empty(self):
        self.assertEqual(parse_gradle_lockfile(os.path.join(self._tmp(), "nope.lockfile")), [])

    def test_empty_file_returns_empty(self):
        path = self._write("gradle.lockfile", "")
        self.assertEqual(parse_gradle_lockfile(path), [])


class ParseMavenPomDependenciesTests(TmpDirMixin, unittest.TestCase):
    def test_pom_with_namespace(self):
        xml = """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter</artifactId>
      <version>3.2.0</version>
    </dependency>
  </dependencies>
</project>"""
        path = self._write("pom.xml", xml)
        deps = parse_maven_pom_dependencies(path)
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0].uri, "pkg:maven/org.springframework.boot/spring-boot-starter@3.2.0")
        self.assertEqual(deps[0].digest, {})

    def test_unresolved_property_placeholder_skipped(self):
        xml = """<project>
  <dependencies>
    <dependency>
      <groupId>org.foo</groupId>
      <artifactId>bar</artifactId>
      <version>${bar.version}</version>
    </dependency>
    <dependency>
      <groupId>org.foo</groupId>
      <artifactId>baz</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>"""
        path = self._write("pom.xml", xml)
        deps = parse_maven_pom_dependencies(path)
        self.assertEqual([d.uri for d in deps], ["pkg:maven/org.foo/baz@1.0.0"])

    def test_missing_fields_skipped(self):
        xml = """<project><dependencies>
          <dependency><groupId>org.foo</groupId><artifactId>bar</artifactId></dependency>
        </dependencies></project>"""
        path = self._write("pom.xml", xml)
        self.assertEqual(parse_maven_pom_dependencies(path), [])

    def test_unresolved_group_or_artifact_id_placeholder_skipped(self):
        xml = """<project><dependencies>
          <dependency>
            <groupId>${project.groupId}</groupId>
            <artifactId>${project.artifactId}</artifactId>
            <version>1.0.0</version>
          </dependency>
        </dependencies></project>"""
        path = self._write("pom.xml", xml)
        self.assertEqual(parse_maven_pom_dependencies(path), [])

    def test_plugin_configuration_dependency_element_not_a_real_dependency(self):
        # Real shape from google/gson's pom.xml: japicmp-maven-plugin's
        # <oldVersion><dependency> is a comparison-baseline coordinate
        # pointer inside plugin <configuration>, not a project dependency
        # -- must not be mistaken for one just because it reuses the tag
        # name outside any real <dependencies> collection.
        xml = """<project>
  <dependencies>
    <dependency>
      <groupId>org.foo</groupId>
      <artifactId>real-dep</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
  <build>
    <plugins>
      <plugin>
        <groupId>com.github.siom79.japicmp</groupId>
        <artifactId>japicmp-maven-plugin</artifactId>
        <configuration>
          <oldVersion>
            <dependency>
              <groupId>${project.groupId}</groupId>
              <artifactId>${project.artifactId}</artifactId>
              <version>0.0.0-JAPICMP-OLD</version>
            </dependency>
          </oldVersion>
        </configuration>
      </plugin>
    </plugins>
  </build>
</project>"""
        path = self._write("pom.xml", xml)
        deps = parse_maven_pom_dependencies(path)
        self.assertEqual([d.uri for d in deps], ["pkg:maven/org.foo/real-dep@1.0.0"])

    def test_plugin_level_dependency_still_counted(self):
        # A <plugin><dependencies><dependency> block is a real Maven
        # construct (plugin-level extra classpath dependency) -- the
        # <dependencies> scoping fix must not exclude it.
        xml = """<project>
  <build>
    <plugins>
      <plugin>
        <groupId>org.foo</groupId>
        <artifactId>some-plugin</artifactId>
        <dependencies>
          <dependency>
            <groupId>org.foo</groupId>
            <artifactId>plugin-dep</artifactId>
            <version>2.0.0</version>
          </dependency>
        </dependencies>
      </plugin>
    </plugins>
  </build>
</project>"""
        path = self._write("pom.xml", xml)
        deps = parse_maven_pom_dependencies(path)
        self.assertEqual([d.uri for d in deps], ["pkg:maven/org.foo/plugin-dep@2.0.0"])

    def test_malformed_xml_returns_empty(self):
        path = self._write("pom.xml", "<project><unclosed>")
        self.assertEqual(parse_maven_pom_dependencies(path), [])

    def test_missing_file_returns_empty(self):
        self.assertEqual(parse_maven_pom_dependencies(os.path.join(self._tmp(), "nope.xml")), [])


class DetectAndParseDependenciesTests(TmpDirMixin, unittest.TestCase):
    def test_aggregates_across_ecosystems(self):
        d = self._tmp()
        self._write(
            "uv.lock",
            '[[package]]\nname = "pytest"\nversion = "8.3.2"\n'
            'source = { registry = "https://pypi.org/simple" }\n',
            tmp_dir=d,
        )
        import json

        self._write(
            "package-lock.json",
            json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.21"}}}),
            tmp_dir=d,
        )
        h1 = base64.b64encode(hashlib.sha256(b"x").digest()).decode("ascii")
        self._write("go.sum", f"github.com/gin-gonic/gin v1.9.1 h1:{h1}\n", tmp_dir=d)
        self._write(
            "gradle.lockfile",
            "com.google.guava:guava:31.1-jre=compileClasspath\n",
            tmp_dir=d,
        )
        self._write(
            "pom.xml",
            "<project><dependencies><dependency>"
            "<groupId>org.foo</groupId><artifactId>bar</artifactId><version>1.0.0</version>"
            "</dependency></dependencies></project>",
            tmp_dir=d,
        )

        results = detect_and_parse_dependencies(d)
        uris = {r["uri"] for r in results}
        self.assertEqual(
            uris,
            {
                "pkg:pypi/pytest@8.3.2",
                "pkg:npm/lodash@4.17.21",
                "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
                "pkg:maven/com.google.guava/guava@31.1-jre",
                "pkg:maven/org.foo/bar@1.0.0",
            },
        )
        self.assertTrue(all(isinstance(r, dict) and "uri" in r and "digest" in r for r in results))

    def test_pnpm_and_pip_compile_detected_too(self):
        d = self._tmp()
        self._write(
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n\npackages:\n\n"
            "  ts-node@10.9.2:\n"
            "    resolution: {integrity: sha512-f0FFpIdcHgn8zcPSbf1dRevwt047YMnaiJM3u2w2RewrB+fob/zePZcrOyQoLMMO7aBIddLcQIEK5dYjkLnGrQ==}\n",
            tmp_dir=d,
        )
        self._write(
            "requirements.txt",
            "attrs==23.1.0 \\\n    --hash=sha256:" + "a" * 64 + "\n",
            tmp_dir=d,
        )
        results = detect_and_parse_dependencies(d)
        uris = {r["uri"] for r in results}
        self.assertEqual(uris, {"pkg:npm/ts-node@10.9.2", "pkg:pypi/attrs@23.1.0"})

    def test_hand_written_requirements_txt_contributes_nothing(self):
        d = self._tmp()
        self._write("requirements.txt", "requests==2.31.0\nflask>=2.0\n", tmp_dir=d)
        self.assertEqual(detect_and_parse_dependencies(d), [])

    def test_dedup_by_uri_first_seen_wins(self):
        d = self._tmp()
        sub = os.path.join(d, "moduleA")
        os.makedirs(sub)
        self._write(
            "gradle.lockfile",
            "com.google.guava:guava:31.1-jre=compileClasspath\n",
            tmp_dir=d,
        )
        self._write(
            "gradle.lockfile",
            "com.google.guava:guava:31.1-jre=runtimeClasspath\n",
            tmp_dir=sub,
        )
        results = detect_and_parse_dependencies(d)
        matching = [r for r in results if r["uri"] == "pkg:maven/com.google.guava/guava@31.1-jre"]
        self.assertEqual(len(matching), 1)

    def test_skips_vendored_directories(self):
        d = self._tmp()
        nm = os.path.join(d, "node_modules", "some-pkg")
        os.makedirs(nm)
        with open(os.path.join(nm, "go.sum"), "w", encoding="utf-8") as f:
            h1 = base64.b64encode(hashlib.sha256(b"x").digest()).decode("ascii")
            f.write(f"github.com/should/not-be-found v1.0.0 h1:{h1}\n")
        self.assertEqual(detect_and_parse_dependencies(d), [])

    def test_no_lockfiles_present_returns_empty(self):
        self.assertEqual(detect_and_parse_dependencies(self._tmp()), [])

    def test_nonexistent_dir_returns_empty(self):
        self.assertEqual(detect_and_parse_dependencies(os.path.join(self._tmp(), "does-not-exist")), [])

    def test_file_not_dir_returns_empty(self):
        path = self._write("not-a-dir.txt", "hi")
        self.assertEqual(detect_and_parse_dependencies(path), [])

    def test_null_byte_path_returns_empty(self):
        self.assertEqual(detect_and_parse_dependencies("repo\x00evil"), [])


if __name__ == "__main__":
    unittest.main()
