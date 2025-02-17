import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description="jpgpdfthing")
    parser.add_argument("pdfile", help="pdf file to embed")
    parser.add_argument("jpgfile", help="jpg file to embed")
    parser.add_argument("output", help="outfile to write")
    args = parser.parse_args()

    try:
        with open(args.jpgfile, "rb") as jpg:
            jpgheader = jpg.read(0x14)
            ## header needs to fit this length or some shit
            if len(jpgheader) != 0x14:
                print("WHERE", file=sys.stderr)
                return 1

            jpgdata = jpg.read()
            if not jpgdata:
                print("ts is not a jpg", file=sys.stderr)
                return 1

        with open(args.pdfile, "rb") as pdf:
            pdfshit = pdf.read()
            if not pdfshit:
                print("ts is not a pdf", file=sys.stderr)
                return 1

        with open(args.output, "wb") as out:
            out.write(jpgheader)

            out.write(b"\xff\xfe\x00\x22\x0a%PDF-1.5\x0a999 0 obj\x0a<<>>\x0astream\x0a")

            start_pos = jpgdata.find(b"\xff\xdb")
            if start_pos == -1:
                print("where is the marker vro", file=sys.stderr)
                return 1
            out.write(jpgdata[start_pos:])

            out.write(b"endstream\x0aendobj\x0a")

            out.write(pdfshit)

        print(f"mashed {args.jpgfile} and {args.pdfile} into {args.output}")
        return 0

    except IOError as e:
        print(f"error in iostream: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
