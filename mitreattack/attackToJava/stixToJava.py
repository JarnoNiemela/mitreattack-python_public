from mitreattack.attackToExcel import stixToDf
from stix2 import Filter, MemoryStore


from pprint import pprint
from loguru import logger

import os
import jinja2
import shutil

script_dir = os.path.dirname(os.path.realpath(__file__))
template_dir = os.path.join(script_dir, "templates")


def buildOutputDir(package_name: str, domain: str, output_dir: str = "."):
    """
    Build the output directory for the Java classes

    Parameters
    ----------
    package_name : str
        The name of the package to create the directory for

    domain : str
        The domain of ATT&CK to download, e.g "enterprise-attack"

    Returns
    -------
    str
        The path to the output directory
    """

    #Remove the output directory if it exists
    if os.path.exists(os.path.join(output_dir, package_name.replace(".", os.sep))):
        shutil.rmtree(os.path.join(output_dir, package_name.replace(".", os.sep)))


    class_tree_base = os.path.join(output_dir, package_name.replace(".", os.sep), domain.replace("-attack", ""))

    os.makedirs(class_tree_base, exist_ok=True)

    #Copy AttackMatrix.java from script directory to output directory using shutil.copyfile
    attack_matrix_file = "AttackMatrix.jinja2"
    output_attack_matrix_file = os.path.join(output_dir, package_name.replace(".", os.sep), "AttackMatrix.java")

    fields = {
        "package_name": package_name,
    }
    #Use Jinja2 to load and render the template
    templateLoader = jinja2.FileSystemLoader(searchpath=template_dir)
    templateEnv = jinja2.Environment(loader=templateLoader)
    template = templateEnv.get_template(attack_matrix_file)
    outputText = template.render(fields)
    with open(output_attack_matrix_file, "w") as f:
        logger.info(f"Writing {output_attack_matrix_file}")
        f.write(outputText)


def stixToTactics(stix_data: MemoryStore, package_name: str, domain: str , verbose_class: bool = False, output_dir: str ="."):

    #Add Tactic to the base package name
    domain_bare = domain.replace("-attack", "")
    package_name = f"{package_name}.{domain_bare}.tactic"

    package_dir = os.path.join(output_dir, package_name.replace(".", os.sep) )
    os.makedirs(package_dir, exist_ok=True)

    tactics = stix_data.query([Filter("type", "=", "x-mitre-tactic")])
    tactics = stixToDf.remove_revoked_deprecated(tactics)

    #Use Jinja2 to load and render the template
    templateLoader = jinja2.FileSystemLoader(searchpath=template_dir)
    templateEnv = jinja2.Environment(loader=templateLoader)
    
    tactic_rows = []
    for tactic in tactics:
        tactic_rows.append(stixToDf.parseBaseStix(tactic))
    

    for tactic in tactic_rows:
        tactic["domain"]= domain
        
        pprint(tactic)

        #Make sure name field does not have spaces and every word is capitalized
        name_parts=tactic["name"].split(" ")
        tactic["name"] = "".join([part.capitalize() for part in name_parts])
        
        template = templateEnv.get_template("Tactic.jinja2")
        outputText = template.render(tactic)
        
        output_file = os.path.join(package_dir, f"{tactic['name']}.java")
        with open(output_file, "w") as f:
            logger.info(f"Writing {output_file}")
            f.write(outputText)
            




        