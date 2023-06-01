#!/usr/bin/env python3
import click
import platform
from os import getenv
from junitparser import JUnitXml

def load_junit_xml(file):
    print(f'Loading {file.name}')
    return JUnitXml.fromfile(file)

@click.group()
def cli():
    """Command line entry point"""
    pass

@cli.command()
@click.argument('file', type=click.File('r'), nargs=-1)
def merge(file):
    """
    Iterate over the files, merging them into a single XML file.
    Inject some metadata for arcitecture and libcrypto.
    """
    newxml = JUnitXml()
    for xml in file: 
        if file.index(xml) == 0:
            newxml = load_junit_xml(xml)
        else:
            tmpxml = load_junit_xml(xml)
            newxml+= tmpxml
    # Because xdist messes with pytest's abiltiy to inject metadata,
    # we're adding values after merging the files.
    for suite in newxml:
        suite.add_property('arch', platform.machine())
        suite.add_property('S2N_LIBCRYPTO', getenv('S2N_LIBCRYPTO'))
    # Use the first filenames upto '_' as a prefex for the final file.
    if '_' in file[0].name:
        fileprefix = file[0].name.split('_')[0]
    else:
        # Fallback file prefix
        fileprefix = 'junit'
    newxml.write(f'{fileprefix}_summary.xml')
    print(f'Wrote {fileprefix}_summary.xml')

if __name__ == '__main__':
    cli()
