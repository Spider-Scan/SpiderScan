from __future__ import annotations

import subprocess


def inject_dockerfile(package_path: str):
    config = '''version: "2"
services:
  node:
    image: "node:20"
    user: "root"
    working_dir: /home/node/app
    environment:
      - NODE_ENV=production
    volumes:
      - ./:/home/node/app
    command: "npm install"
'''
    with open(f"{package_path}/docker-compose.yml", "w") as f:
        f.write(config)


def docker_eval(package_path: str) -> dict[str, str] | None:
    inject_dockerfile(package_path)
    try:
        subprocess.run(['docker-compose', 'up'],
                       cwd=package_path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    except Exception as e:
        pass
    finally:
        subprocess.run(['docker-compose', 'rm', '-fsv'],
                       cwd=package_path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    results = {}
    try:
        with open(f"{package_path}/log.log", "r") as f:
            loglines = f.readlines()
    except Exception:
        return None

    for line in loglines:
        var, val = line.split(":", maxsplit=1)
        results[var] = val.strip()
    return results
