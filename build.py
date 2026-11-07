import argparse
from pathlib import Path

import PyInstaller.__main__


def build(output_dir: str = "dist", work_dir: str = "build"):
    project_dir = Path(__file__).parent.resolve()
    PyInstaller.__main__.run([
        str(project_dir / "scanfuse.spec"),
        '--clean',
        '--noconfirm',
        f'--distpath={project_dir / output_dir}',
        f'--workpath={project_dir / work_dir}',
        '--log-level=WARN',
    ])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build the standalone scanfuse executable.")
    parser.add_argument("--output-dir", default="dist")
    parser.add_argument("--work-dir", default="build")
    args = parser.parse_args()
    build(args.output_dir, args.work_dir)
