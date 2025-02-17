import os
import sys

def rf(filename):
    with open(filename, 'rb') as f:
        return f.read()

def ecd(zipd):
    ecdsig = b'\x50\x4B\x05\x06'
    for i in range(len(zipd) - 4, -1, -1):
        if zipd[i:i+4] == ecdsig:
            return i
    raise ValueError("cant find ecd on zip bro.")

def main():
    if len(sys.argv) != 4:
        print("params are: image file out")
        sys.exit(1)

    image, file, out = sys.argv[1], sys.argv[2], sys.argv[3]

    imgdata = rf(image)
    if len(imgdata) < 2 or imgdata[-2:] != b'\xff\xd9':
        imgdata += b'\xff\xd9'
    imgsize = len(imgdata)
    
    zipd = rf(file)

    ecdp = ecd(zipd)
    ecdd = zipd[ecdp:ecdp+22]


    cd_size = int.from_bytes(ecdd[12:16], 'little')
    cdoff = int.from_bytes(ecdd[16:20], 'little')
    comment_length = int.from_bytes(ecdd[20:22], 'little')

    centraldird = zipd[cdoff : cdoff + cd_size]
    cdata = zipd[ecdp+22 : ecdp+22+comment_length]

    centraldird = bytearray()
    current = 0
    while current < len(centraldird):
        signature = centraldird[current:current+4]
        if signature != b'\x50\x4B\x01\x02':
            raise ValueError("Invalid central directory entry")
        
        fixed = centraldird[current:current+46]
        flen = int.from_bytes(fixed[28:30], 'little')
        xflen = int.from_bytes(fixed[30:32], 'little')
        commentlen = int.from_bytes(fixed[32:34], 'little')
        
        filename = centraldird[current+46 : current+46+flen]
        extraf = centraldird[current+46+flen : current+46+flen+xflen]
        fcomment = centraldird[current+46+flen+xflen : current+46+flen+xflen+commentlen]
        
        reloffset = int.from_bytes(fixed[42:46], 'little')
        noffset = reloffset + imgsize
        
        new_entry = (
            fixed[:42] +
            noffset.to_bytes(4, 'little') +
            filename +
            extraf +
            fcomment
        )
        centraldird.extend(new_entry)
        
        current += 46 + flen + xflen + commentlen

    offset = cdoff + imgsize
    modecd = (
        ecdd[:16] +
        offset.to_bytes(4, 'little') +
        ecdd[20:]
    )

    localdata = zipd[:cdoff]
    modzipd = (
        localdata +
        bytes(centraldird) +
        modecd +
        cdata
    )

    polyglot = imgdata + modzipd

    with open(out, 'wb') as f:
        f.write(polyglot)
    print(out)

if __name__ == "__main__":
    main()
