# LRIT
LRIT decoding python code

## Use

Set up config.json to point the LRIT receiver you have.

python lrit.py --config config.json


## Emwin

If config.json if configured to output emwin data, Virtual Channel 0, type 214

you can use the emwin program to generate individual files:

cd <whereever you have the emwin LRIT files>
cat * python <path to emwin>/emwin

You will now have a bunch of text, zip and a few image files.
