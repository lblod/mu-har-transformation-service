#!/usr/bin/env python2

import argparse
import os
import errno
import json
import signal
import sys
import getopt
import requests
import shutil
import time
import logging
import base64
import yaml
import random
import subprocess
import urllib2
from SPARQLWrapper import SPARQLWrapper, JSON
from urllib2 import URLError

har_output_dir = os.environ['HAR_OUTPUT_DIR']
container_data_dir = os.environ['CONTAINER_DATA_DIR']
container_data_file = os.environ['CONTAINER_DATA_FILE']
sleep_period = os.environ['SLEEP_PERIOD']
sparqlQuery = SPARQLWrapper(os.environ.get('MU_SPARQL_ENDPOINT'), returnFormat=JSON)

def query(query):
    """
    Queries the SPARQL endpoint2
    """
    logger.debug(query)
    sparqlQuery.setQuery(query)
    return sparqlQuery.query().convert()

def load_json_from_file( har_file ):
    """
    Loads a json from disk and parses it.  Retries when the file fails to load

    Sometimes decoding fails, supposedly because the har file was not written
    completely yet.  Retrying by sleeping for a moment and syncing the filesystem.
    """
    for attempt in range(10):
        try:
            return json.loads(open(har_file).read())
        except:
            time.sleep(2)
            subprocess.Popen("sync", shell=True).wait()
            continue
        else:
            raise ValueError("Could not process json file " + har_file)

def get_module_logger(mod_name):
    """
    To use this, do logger = get_module_logger(__name__)
    """
    logger = logging.getLogger(mod_name)
    handler = logging.StreamHandler()
    formatter = logging.Formatter('[%(levelname)-4s] %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Create a handler that will log into a file.
    logfile = 'har_' + str(random.getrandbits(32)) + '.log'
    fileHandler = logging.FileHandler(logfile)
    fileHandler.setFormatter(formatter)
    logger.addHandler(fileHandler)

    logger.setLevel(logging.DEBUG)
    return logger


logger = get_module_logger(__name__)


def transform_pcap(pcap_file, inputfolder, outputfolder):
    """
    Transforms a single .pcap file into a .har file.

    Args:
        pcap_file: the pcap file
        inputfolder: the input folder.
        outputfolder: the output folder.
    Raises:
        OSError: if there is a race condition while making a directory in the outut folder, this error will arise.
    """
    output_name = os.path.join(outputfolder, pcap_file) + ".har"
    cmd = "python pcap2har {input} {output}".format(input=os.path.join(inputfolder, pcap_file), output=output_name)
    subprocess.Popen(cmd, shell=True).wait()
    return output_name

def network_monitors():
    results = query("""
       PREFIX logger:<http://mu.semte.ch/vocabularies/ext/docker-logger/>
       PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
       PREFIX docker: <https://w3.org/ns/bde/docker#>
       SELECT ?id ?name ?uri ?status ?path ?composeProject ?composeService ?composeContainerNumber
       WHERE {
        ?uri a logger:NetworkMonitor;
             mu:uuid ?id;
             logger:status ?status;
             logger:path ?path;
             logger:monitors ?dockerContainer.
       ?dockerContainer docker:name ?name.
       OPTIONAL {
         ?dockerContainer docker:label ?labelP.
         ?labelP docker:key "com.docker.compose.project";
                 docker:value ?composeProject.
         ?dockerContainer docker:label ?labelS.
         ?labelS docker:key "com.docker.compose.service";
                 docker:value ?composeService.
         ?dockerContainer docker:label ?labelC.
         ?labelC docker:key "com.docker.compose.container-number";
                 docker:value ?composeContainerNumber.
       }
    }
    """)
    return results["results"]["bindings"]

def enrich_har(monitor, har_file):
    """
    Modifies an existing HAR file with additional information about the container
    it involves and the links to other containers. Also converts base64 strings
    back into JSON format.
    Information is repeated in each entry because each one will need to be posted
    sepparately into ElasticSearch.

    Args:
        har_file: the har file
    """
    decoded = load_json_from_file( har_file )
    if not monitor.has_key("composeProject") or not monitor.has_key("composeService"):
        print "Cannot monitor container outside of service ", monitor["id"], " ", monitor["name"]
        return
    elif monitor["composeProject"].has_key('value'):
        meta_info = {
            'compose-project': monitor["composeProject"]["value"],
            'compose-service': monitor["composeService"]["value"],
            'compose-container-number': monitor["composeContainerNumber"]["value"]
        }
    else:
        meta_info = {}
    result = parse_recursive_har(meta_info, decoded, har_file)

    newname = har_file[:-4] + '.trans.har'
    with open(newname, 'w') as f:
        json.dump(result, f, indent=2, encoding='utf8', sort_keys=True)
        f.write('\n')

    return newname


def parse_recursive_har(meta, har, har_name, isBase64 = False, isEntry = False):
    """
    Transform the har object decoding the base64 strings into JSON objects.

    Args:
        har: a single HAR (json) object.
    """
    result = {}
    # If it is one of the entries in the entries[] array, enrich it with additional information.
    if isEntry == True:
        result['meta'] = meta

    # Loop through the keys in the HAR file
    for attr, value in har.iteritems():
        # If we stumble upon base64 content, we call the function to decode it.
        if (type(har[attr]) is dict) and (attr == "content"):
            if "encoding" in har[attr].keys() and har[attr]["encoding"] == "base64" and (har[attr]["mimeType"] == "application/json" or har[attr]["mimeType"] == "application/vnd.api+json" or har[attr]["mimeType"] == "application/sparql-results+json"):
                result[attr] = parse_recursive_har(meta, har[attr], har_name, True)
            else:
                result[attr] = parse_recursive_har(meta, har[attr], har_name)
        # If the key is a dictionary just loop through it.
        elif type(har[attr]) is dict:
            result[attr] = parse_recursive_har(meta, har[attr], har_name)
        # If the key is a list, some data transformation is needed.
        elif type(har[attr]) is list:
            result[attr] = []
            if attr == "entries": # Enrich each entry in the entries[] array.
                for i, val in enumerate(har[attr]):
                    result[attr].append(parse_recursive_har(meta, val, har_name, False, True))
            elif attr == "headers": # Convert headers from an array into an object.
                result[attr] = { header['name']: header['value'] for header in har[attr] }
            else:
                for i, val in enumerate(har[attr]):
                    result[attr].append(parse_recursive_har(meta, val, har_name))
        # If it is a value in base64 (previously detected) then decode it, otherwise return it as is.
        else:
            if attr == "text" and isBase64 == True:
                result[attr] = base64.b64decode(value)
                try:
                    result["json"] = json.loads( result[attr] )
                except:
                    logger.info( "Failed to parse JSON content of har " + har_name + " with content " + result[attr] );
            else:
                result[attr] = value
    return result

def transformation_pipeline(monitor, inputfolder, outputfolder, processedfolder):
    """
    Watches the folder inputfolder for new unobserved pcap files and converts them into har format.

    Args:
        monitor: meta information about the pcaps
        inputfolder: input folder to look for pcap files.
        outputfolder: output folder to save the converted har files.
    """
    for root, dirs, files in os.walk(inputfolder):
        for fich in files:
            if fich.endswith(".pcap"):
                logger.info("[+] File: {pcap} not yet transformed. Transforming it..".format(pcap=fich))
                # PCAP to HAR
                har_name = transform_pcap(fich, inputfolder, outputfolder)
                shutil.move(os.path.join(inputfolder, fich), os.path.join(processedfolder, fich))
                # ENRICH HAR
                logger.info("[+] File: {har} not yet enriched. Enriching it..".format(har=os.path.basename(har_name)))
                enriched_har_name = enrich_har(monitor, har_name)
                if enriched_har_name:
                    shutil.move(har_name, os.path.join(processedfolder, os.path.basename(har_name)))

def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

if __name__ == '__main__':
    notUp = True
    while notUp:
        try:
            notUp = not query("ASK {?s ?p ?o}")
        except URLError as e:
            pass
        if notUp:
            time.sleep(2.0)
            logger.info('SPARQL endpoint not available, waiting for 2 seconds')
    while True:
        for monitor in network_monitors():
            logger.info('checking for pcap files for container' + monitor["name"]["value"])
            pcap_dir = monitor["path"]["value"].replace('share://','/data/pcaps/')
            if os.path.exists(pcap_dir):
                har_dir = monitor["path"]["value"].replace('share://','/data/hars/')
                processed_dir = monitor["path"]["value"].replace('share://','/data/processed/')
                mkdir_p(har_dir)
                mkdir_p(processed_dir)
                transformation_pipeline(monitor, pcap_dir, har_dir, processed_dir )
            else:
                logger.error('The directory' + pcap_dir + ' does not exist')
        time.sleep(float(sleep_period))
