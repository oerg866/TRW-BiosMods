import os
import shutil
import subprocess
import sys
import tempfile

# Small helper script to return bytes for a given assembly instruction in MASM format
# Might be useful since online playgrounds are buggy or keep dying or don't support 16-bit real mode stuff
# Requires MASM 6.1x as well as an appropriate LINK.EXE (e.g. 5.60.339) to be installed and in path

ML = shutil.which("ml.exe") or "ml.exe"
LINK = shutil.which("link.exe") or "link.exe"

def assemble(instr):
    with tempfile.TemporaryDirectory() as tmp:
        asm = os.path.join(tmp, "temp.asm")
        obj = os.path.join(tmp, "temp.obj")
        com = os.path.join(tmp, "temp.com")

        with open(asm, "w") as f:
            f.write(f"""
OPTION SEGMENT:USE16
.386p
.model tiny
.code
org 100h

start:
    {instr}

end start
""")

        # Assemble
        r = subprocess.run( [ML, "/nologo", "/c", asm], cwd=tmp, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        if r.returncode != 0:
            raise RuntimeError(r.stdout)

        # Link to COM, the semicolon suppresses interactive prompts
        r = subprocess.run([LINK, "/TINY", obj + ",", com + ",,;", ], cwd=tmp, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        if r.returncode != 0:
            raise RuntimeError(r.stdout)

        return open(com, "rb").read()

def shell():
    print("MASM x86 assembler shell.")
    print("Type 'exit' or 'quit' to leave.\n")

    while True:
        try:
            instr = input("X86> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not instr:
            continue

        if instr.lower() in ("exit", "quit"):
            break

        try:
            code = assemble(instr)
            print(" ".join(f"{b:02X}" for b in code))
        except Exception as e:
            print(f"Error: {e}")
            
def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "-shell":
        shell()
        return

    if len(sys.argv) < 2:
        print("Usage:")
        print("  x86asm.py <MASM instruction>")
        print("  x86asm.py -shell")
        sys.exit(1)

    instr = " ".join(sys.argv[1:])

    try:
        code = assemble(instr)
        print(" ".join(f"{b:02X}" for b in code))
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
