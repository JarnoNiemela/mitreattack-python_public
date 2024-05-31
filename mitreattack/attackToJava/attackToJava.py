"""Functions to convert ATT&CK STIX data to Java, as well as entrypoint for attackToJava_cli."""

import argparse
import os
from typing import Dict, List

import pandas as pd
import requests
from loguru import logger
from stix2 import MemoryStore
from pprint import pprint

INVALID_CHARACTERS = ["\\", "/", "*", "[", "]", ":", "?"]
SUB_CHARACTERS = ["\\", "/"]

from mitreattack.attackToExcel import attackToExcel
from mitreattack.attackToJava import stixToJava



def export(
    domain: str = "enterprise-attack",
    version: str = None,
    output_dir: str = ".",
    remote: str = None,
    stix_file: str = None,
    package_name: str = "org.mitre.attack",
    verbose_class: bool = False,
    ):
    """Download ATT&CK data from MITRE/CTI and convert it to Java class hierarchy

    Parameters
    ----------
    domain : str, optional
        The domain of ATT&CK to download, e.g "enterprise-attack", by default "enterprise-attack"
    version : str, optional
        The version of ATT&CK to download, e.g "v8.1".
        If omitted will build the current version of ATT&CK, by default None
    output_dir : str, optional
        The directory to write the excel files to.
        If omitted writes to a subfolder of the current directory depending on specified domain and version, by default "."
    remote : str, optional
        The URL of a remote ATT&CK Workbench instance to connect to for stix data.
        Mutually exclusive with stix_file.
        by default None
    stix_file : str, optional
        Path to a local STIX file containing ATT&CK data for a domain, by default None

    Raises
    ------
    ValueError
        Raised if both `remote` and `stix_file` are passed
    """
    if remote and stix_file:
        raise ValueError("remote and stix_file are mutually exclusive. Please only use one or the other")
    
    stixToJava.buildOutputDir(package_name=package_name, domain=domain, output_dir=output_dir)
    
    mem_store = attackToExcel.get_stix_data(domain=domain, version=version, remote=remote, stix_file=stix_file)

    stixToJava.stixToTactics(stix_data=mem_store, package_name=package_name, domain=domain, verbose_class=verbose_class,output_dir=output_dir)

    logger.info(f"************ Exporting {domain} to To Java ************")


def main():
    """Entrypoint for attackToExcel_cli."""
    parser = argparse.ArgumentParser(
        description="Download ATT&CK data from MITRE/CTI and convert it to excel spreadsheets"
    )
    parser.add_argument(
        "-domain",
        type=str,
        choices=["enterprise-attack", "mobile-attack", "ics-attack"],
        default="enterprise-attack",
        help="which domain of ATT&CK to convert",
    )
    parser.add_argument(
        "-version",
        type=str,
        help="which version of ATT&CK to convert. If omitted, builds the latest version",
    )
    parser.add_argument(
        "-output",
        type=str,
        default=".",
        help="output directory. If omitted writes to a subfolder of the current directory depending on "
        "the domain and version",
    )
    parser.add_argument(
        "-remote",
        type=str,
        default=None,
        help="remote url of an ATT&CK workbench server. If omitted, stix data will be acquired from the"
        " official ATT&CK Taxii server (cti-taxii.mitre.org)",
    )
    parser.add_argument(
        "-stix-file",
        type=str,
        default=None,
        help="Path to a local STIX file containing ATT&CK data for a domain, by default None",
    )

    parser.add_argument(
        "-package",
        type=str,
        default="org.mitre.attack",
        help="Java package name from which to start the class hierarchy. If omitted, will use the org.mitre.attack followed by domain with '-attack' removed.",
    )

    parser.add_argument(
        "-verbose",
        action="store_true",
        help="Populate all fields in Java class, including description and other non-essential. Note this will increase memory usage and file size.",
    )       
    args = parser.parse_args()

    export(
        domain=args.domain, version=args.version, output_dir=args.output, remote=args.remote, stix_file=args.stix_file, package_name=args.package, verbose_class=args.verbose
    )


if __name__ == "__main__":
    main()
