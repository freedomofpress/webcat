from os import makedirs
from os.path import abspath, join
from tempfile import TemporaryDirectory
from subprocess import run

def generate_bundle(path):
    path = abspath(path)
    with TemporaryDirectory() as tmp:
        run(["sigsum-key", "generate", "-o", "key1"], cwd=tmp, check=True)
        hex1 = run(["sigsum-key", "to-hex", "-k", "key1.pub"], cwd=tmp, check=True, capture_output=True, text=True)
        run(["sigsum-key", "generate", "-o", "key2"], cwd=tmp, check=True)
        hex2 = run(["sigsum-key", "to-hex", "-k", "key2.pub"], cwd=tmp, check=True, capture_output=True, text=True)
        with open(join(tmp, "trust_policy"), "w", encoding="utf-8") as trust_policy:
            trust_policy.write("log 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6 https://test.sigsum.org/barreleye\n")
            trust_policy.write("\n")
            trust_policy.write("witness poc.sigsum.org/nisse 1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c\n")
            trust_policy.write("witness rgdd.se/poc-witness  28c92a5a3a054d317c86fc2eeb6a7ab2054d6217100d0be67ded5b74323c5806\n")
            trust_policy.write("\n")
            trust_policy.write("group  demo-quorum-rule any poc.sigsum.org/nisse rgdd.se/poc-witness\n")
            trust_policy.write("quorum demo-quorum-rule\n")
        run(["webcat", "enrollment", "create",
             "--policy-file", "trust_policy",
             "--threshold", "1",
             "--max-age", "15552000",
             "--cas-url", "https://cas.demoelement.com",
             "--signer", hex1.stdout,
             "--signer", hex2.stdout,
             "--output", "enrollment.json"],
             cwd=tmp, check=True)
        run(["webcat", "manifest", "generate",
             "--policy-file", "trust_policy",
             "--config", join(path, "webcat.config.json"),
             "--directory", path,
             "--output", "manifest_unsigned.json"],
            cwd=tmp, check=True)
        run(["webcat", "manifest", "sign",
             "--policy-file", "trust_policy",
             "-i", "manifest_unsigned.json",
             "-k", "key1",
             "-o", "manifest.json"],
            cwd=tmp, check=True)
        makedirs(join(path, ".well-known/webcat"), exist_ok=True)
        run(["webcat", "bundle", "create",
             "--enrollment", "enrollment.json",
             "--manifest", "manifest.json",
             "--output", join(path, ".well-known/webcat/bundle.json")],
            cwd=tmp, check=True)
