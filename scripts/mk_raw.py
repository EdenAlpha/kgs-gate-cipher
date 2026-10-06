"""Write a raw one-line cmd file with zero shell expansion (PowerShell eats $())."""
import sys

OUT = sys.argv[1]
line = sys.argv[2]
with open(OUT, "w", newline="\n") as fh:
    fh.write(line)
print("wrote %d bytes: %s..." % (len(line), line[:60]))
