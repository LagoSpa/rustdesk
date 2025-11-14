#!/bin/bash

command -v "magick" &> /dev/null || exit 1
command -v "inkscape" &> /dev/null || exit 1

IN="${1:-"icon.svg"}"
[[ -f "${IN}" ]] || exit 1

inkscape -o icon.png -w 1024 -h 1024 ${IN} &> /dev/null

sizes=""
for size in 16 32 48 64 128 256; do
  inkscape -o ${size}.png -w ${size} -h ${size} ${IN} &> /dev/null
  sizes="${sizes} ${size}.png"
done

magick ${sizes} -colors 256 icon.ico

cp 32.png "tray-icon.ico"

for size in 32 64 128; do
  mv ${size}.png "${size}x${size}.png"
done
mv 256.png "128x128@2x.png"

rm ${sizes} &> /dev/null

# for size in 16 32 64 128 256 512 1024; do
#   inkscape -z -o ${size}.png -w ${size} -h ${size} ${IN} &> /dev/null
# done
