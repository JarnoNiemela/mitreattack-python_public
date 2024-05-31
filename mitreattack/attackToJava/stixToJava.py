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


    class_tree_base = os.path.join(output_dir, package_name.replace(".", os.sep))

    #Remove the output directory if it exists
    if os.path.exists(class_tree_base):
        shutil.rmtree(class_tree_base)

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

def nameToClassName(name: str):
    """Convert a name to a class name

    Parameters
    ----------
    name : str
        The name to convert

    Returns
    -------
    str
        The class name
    """
    #Make sure name field does not have spaces and every word is capitalized
    #There can be " " or "-" or "_" in the name so split by all of them
    name= name.replace("-", " ")
    name= name.replace("_", " ")
    name= name.replace("/", " ")
    name_parts = name.split(" ")
    
    return "".join([part.capitalize() for part in name_parts])

def stixToTactics(stix_data: MemoryStore, package_name: str, domain: str , verbose_class: bool = False, output_dir: str ="."):

    #Add Tactic to the base package name
    domain_bare = domain.replace("-attack", "")
    package_name = f"{package_name}.tactic"

    package_dir = os.path.join(output_dir, package_name.replace(".", os.sep) )
    os.makedirs(package_dir, exist_ok=True)

    tactics = stix_data.query([Filter("type", "=", "x-mitre-tactic")])
    tactics = stixToDf.remove_revoked_deprecated(tactics)

    tactic_rows = []
    for tactic in tactics:
        tactic_rows.append(stixToDf.parseBaseStix(tactic))

    #Use Jinja2 to load and render the template
    templateLoader = jinja2.FileSystemLoader(searchpath=template_dir)
    templateEnv = jinja2.Environment(loader=templateLoader)
    
    
    for tactic in tactic_rows:
        tactic["domain"]= domain
        tactic["package_name"] = package_name
        #Make sure name field does not have spaces and every word is capitalized
        tactic["class_name"] = nameToClassName(tactic["name"])
        
        #Write the Tactic as Interface as techniques commonly can be present in multiple tactics
        template = templateEnv.get_template("Tactic.jinja2")
        outputText = template.render(tactic)
        
        output_file = os.path.join(package_dir, f"{tactic['class_name']}.java")
        with open(output_file, "w") as f:
            logger.info(f"Writing {output_file}")
            f.write(outputText)

        template = templateEnv.get_template("AbstractTactic.jinja2")
        outputText = template.render(tactic)
        
        output_file = os.path.join(package_dir, f"Abstract{tactic['class_name']}.java")
        with open(output_file, "w") as f:
            logger.info(f"Writing {output_file}")
            f.write(outputText)
            

def stixToTechniques(stix_data: MemoryStore,package_name: str, domain , verbose_class: bool = False, output_dir: str ="."):
    """Parse STIX techniques from the given data and write corresponding Java classes

    :param stix_data: MemoryStore or other stix2 DataSource object holding the domain data
    :param domain: domain of ATT&CK stix_data corresponds to, e.g "enterprise-attack"
    """

    techniques = stix_data.query([Filter("type", "=", "attack-pattern")])
    techniques =stixToDf.remove_revoked_deprecated(techniques)
    technique_rows = []

    tactics = stix_data.query([Filter("type", "=", "x-mitre-tactic")])
    tactics =stixToDf.remove_revoked_deprecated(tactics)
    tactic_names = {}
    for tactic in tactics:
        x_mitre_shortname = tactic["x_mitre_shortname"]
        tactic_names[x_mitre_shortname] = tactic["name"]

    all_sub_techniques = stix_data.query(
        [
            Filter("type", "=", "relationship"),
            Filter("relationship_type", "=", "subtechnique-of"),
        ]
    )
    all_sub_techniques = MemoryStore(stix_data=all_sub_techniques)

    for technique in techniques:
        # get parent technique if sub-technique
        #pprint(technique)
        subtechnique = "x_mitre_is_subtechnique" in technique and technique["x_mitre_is_subtechnique"]
        if subtechnique:
            subtechnique_of = all_sub_techniques.query([Filter("source_ref", "=", technique["id"])])[0]
            parent = stix_data.get(subtechnique_of["target_ref"])

        # base STIX properties
        row =stixToDf.parseBaseStix(technique)

        # sub-technique properties
        if "kill_chain_phases" not in technique:
            attack_id = technique['external_references'][0]['external_id']
            logger.error(f"Skipping {attack_id} [{technique['id']}] because it does't have kill chain phases")
            continue
        tactic_shortnames = []
        for kcp in technique["kill_chain_phases"]:
            tactic_shortnames.append(kcp["phase_name"])

        technique_tactic_names = []
        implements = []
        for shortname in tactic_shortnames:
            tactic_display_name = tactic_names[shortname]
            technique_tactic_names.append(tactic_display_name)
            implements.append(f"{package_name}.tactic.{nameToClassName(tactic_display_name)}")
        row["tactics"] = ", ".join(sorted(technique_tactic_names))

        #remove the last comma and space, if they are present
        row["implements"] = False
        if len(implements) > 0:
            row["implements"] = ", ".join(sorted(implements))

        if "x_mitre_detection" in technique:
            row["detection"] = technique["x_mitre_detection"]
        if "x_mitre_platforms" in technique:
            row["platforms"] = ", ".join(sorted(technique["x_mitre_platforms"]))

        # domain specific fields -- ICS + Enterprise
        if domain in ["enterprise-attack", "ics-attack"]:
            if "x_mitre_data_sources" in technique:
                row["data sources"] = ", ".join(sorted(technique["x_mitre_data_sources"]))

        row["class_name"] = nameToClassName(technique['name'])

        # domain specific fields -- enterprise
        if domain == "enterprise-attack":            
            row["is_sub-technique"] = subtechnique
            row["extends"] = f"{package_name}.AttackMatrix"
            if subtechnique:                
                row["sub-technique of"] = parent["external_references"][0]["external_id"]
                row["extends"] = f"{package_name}.technique.{nameToClassName(parent['name'])}"
                row["parent_name"] = nameToClassName(parent['name'])

            if "x_mitre_system_requirements" in technique:
                row["system requirements"] = ", ".join(sorted(technique["x_mitre_system_requirements"]))
            if "x_mitre_permissions_required" in technique:
                row["permissions required"] = ", ".join(
                    sorted(technique["x_mitre_permissions_required"], key=str.lower)
                )
            if "x_mitre_effective_permissions" in technique:
                row["effective permissions"] = ", ".join(
                    sorted(technique["x_mitre_effective_permissions"], key=str.lower)
                )

            if "defense-evasion" in tactic_shortnames and "x_mitre_defense_bypassed" in technique:
                row["defenses bypassed"] = ", ".join(sorted(technique["x_mitre_defense_bypassed"]))
            if "execution" in tactic_shortnames and "x_mitre_remote_support" in technique:
                row["supports remote"] = technique["x_mitre_remote_support"]
            if "impact" in tactic_shortnames and "x_mitre_impact_type" in technique:
                row["impact type"] = ", ".join(sorted(technique["x_mitre_impact_type"]))
            capec_refs = list(
                filter(
                    lambda ref: ref["source_name"] == "capec",
                    technique["external_references"],
                )
            )
            if capec_refs:
                row["CAPEC ID"] = ", ".join([x["external_id"] for x in capec_refs])

        # domain specific fields -- mobile
        elif domain == "mobile-attack":
            if "x_mitre_tactic_type" in technique:
                row["tactic type"] = ", ".join(sorted(technique["x_mitre_tactic_type"]))
            mtc_refs = list(
                filter(
                    lambda ref: ref["source_name"] == "NIST Mobile Threat Catalogue",
                    technique["external_references"],
                )
            )
            if mtc_refs:
                row["MTC ID"] = mtc_refs[0]["external_id"]

        #modify the row dictionary keys so that they do not have spaces, as those can't be used in Jinja2 templates easily
        row = {key.replace(" ", "_"): value for key, value in row.items()}

        pprint(row)

        technique_rows.append(row)
    

    for technique in technique_rows:
        class_package_name = f"{package_name}.technique"

        if(technique["is_sub-technique"]):
            class_package_name = f"{package_name}.technique.{technique['parent_name'].lower()}"

        package_dir = os.path.join(output_dir, class_package_name.replace(".", os.sep) )
        os.makedirs(package_dir, exist_ok=True)

        technique["domain"]= domain
        technique["package_name"] = class_package_name

        #Use Jinja2 to load and render the template
        templateLoader = jinja2.FileSystemLoader(searchpath=template_dir)
        templateEnv = jinja2.Environment(loader=templateLoader)
        
        template = templateEnv.get_template("Technique.jinja2")
        outputText = template.render(technique)
        
        output_file = os.path.join(package_dir, f"{technique['class_name']}.java")
        with open(output_file, "w") as f:
            logger.info(f"Writing {output_file}")
            f.write(outputText)





        