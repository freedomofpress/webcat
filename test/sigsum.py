from os import makedirs
from os.path import abspath, dirname, join
from tempfile import TemporaryDirectory
from subprocess import run

TRUST_POLICY = (
    "log 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6 https://test.sigsum.org/barreleye\n"
    "\n"
    "witness poc.sigsum.org/nisse 1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c\n"
    "witness rgdd.se/poc-witness  28c92a5a3a054d317c86fc2eeb6a7ab2054d6217100d0be67ded5b74323c5806\n"
    "\n"
    "group  demo-quorum-rule any poc.sigsum.org/nisse rgdd.se/poc-witness\n"
    "quorum demo-quorum-rule\n"
)


class BundleGenerator:
    """Holds keys and enrollment so multiple bundles can share one enrollment."""

    def __init__(self):
        self._tmp_ctx = TemporaryDirectory()
        self.tmp = self._tmp_ctx.name
        run(["sigsum-key", "generate", "-o", "key1"], cwd=self.tmp, check=True)
        hex1 = run(["sigsum-key", "to-hex", "-k", "key1.pub"],
                   cwd=self.tmp, check=True, capture_output=True, text=True)
        run(["sigsum-key", "generate", "-o", "key2"], cwd=self.tmp, check=True)
        hex2 = run(["sigsum-key", "to-hex", "-k", "key2.pub"],
                   cwd=self.tmp, check=True, capture_output=True, text=True)
        with open(join(self.tmp, "trust_policy"), "w", encoding="utf-8") as f:
            f.write(TRUST_POLICY)
        run(["webcat", "enrollment", "create",
             "--policy-file", "trust_policy",
             "--threshold", "1",
             "--max-age", "15552000",
             "--cas-url", "https://cas.demoelement.com",
             "--signer", hex1.stdout,
             "--signer", hex2.stdout,
             "--output", "enrollment.json"],
            cwd=self.tmp, check=True)

    def sign(self, source_path, config_path=None, output_path=None):
        """Generate manifest and bundle for content under source_path.

        config_path: webcat.config.json to use (default: source_path/webcat.config.json).
        output_path: bundle.json destination (default: source_path/.well-known/webcat/bundle.json).
        """
        source_path = abspath(source_path)
        config_path = abspath(config_path) if config_path else join(source_path, "webcat.config.json")
        output_path = abspath(output_path) if output_path else join(source_path, ".well-known/webcat/bundle.json")
        run(["webcat", "manifest", "generate",
             "--policy-file", "trust_policy",
             "--config", config_path,
             "--directory", source_path,
             "--output", "manifest_unsigned.json"],
            cwd=self.tmp, check=True)
        run(["webcat", "manifest", "sign",
             "--policy-file", "trust_policy",
             "-i", "manifest_unsigned.json",
             "-k", "key1",
             "-o", "manifest.json"],
            cwd=self.tmp, check=True)
        makedirs(dirname(output_path), exist_ok=True)
        run(["webcat", "bundle", "create",
             "--enrollment", "enrollment.json",
             "--manifest", "manifest.json",
             "--output", output_path],
            cwd=self.tmp, check=True)

    def close(self):
        self._tmp_ctx.cleanup()


def generate_bundle(path):
    g = BundleGenerator()
    try:
        g.sign(path)
    finally:
        g.close()
