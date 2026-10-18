"""Build a derived Cowrie filesystem from an exported bundled baseline."""
import argparse
import pickle
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from deception.personality.cowrie_fs import build_cowrie_tree, verify_cowrie_tree


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True, help="Exported bundled Cowrie fs.pickle")
    parser.add_argument("--output", required=True, help="Output path for derived filesystem")
    args = parser.parse_args()

    with Path(args.base).open("rb") as source:
        base_tree = pickle.load(source)

    derived_tree = build_cowrie_tree(base_tree)
    verify_cowrie_tree(derived_tree)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    with temporary.open("wb") as destination:
        pickle.dump(derived_tree, destination, protocol=4)
    temporary.replace(output)

    with output.open("rb") as check:
        verify_cowrie_tree(pickle.load(check))

    print("Built and verified:", output)
    print("Synthetic virtual assets: 6")


if __name__ == "__main__":
    main()
