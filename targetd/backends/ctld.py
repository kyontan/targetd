# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Copyright 2021, kyontan <kyontan@monora.me>

from dataclasses import dataclass, field
from yaml import dump, load, SafeLoader
from marshmallow_dataclass import class_schema
from typing import Type, Any, List, Optional
from textwrap import indent, dedent
import logging

import os
from signal import SIGHUP

def compose_config(header: str, contents: List[str]):
  return header + " {\n" + "\n".join([indent(c, "  ") for c in contents]) + "\n}"

@dataclass
class CtldPortalGroupConfig:
  listen: str
  name: str = "pg-targetd"
  discovery_auth_group: str = "no-authentication"

  def to_ctl_config(self):
    if self.listen is None:
      raise BaseException("portal listen must be set")
    if self.name is None:
      raise BaseException("portal name must be set")
    if self.discovery_auth_group is None:
      raise BaseException("portal discovery_auth_group must be set")

    header = f"portal-group {self.name}"

    contents = [
      f"listen {self.listen}",
      f"discovery-auth-group {self.discovery_auth_group}",
    ]

    return compose_config(header, contents)

@dataclass
class CtldTargetLunConfig:
  id: int
  path: str
  blocksize: Optional[int] = None

  # not used in ctld. but targetd requires acl could be set and saved
  initiator_wwns: List[str] = field(default_factory=list)

  def to_ctl_config(self):
    if self.id is None:
      raise BaseException("lun id must be set")
    if self.path is None:
      raise BaseException("lun path must be set")

    header = f"lun {self.id}"

    contents = [
      f"path {self.path}",
    ]

    if self.blocksize is not None:
      contents.append(f"blocksize {self.blocksize}")

    return compose_config(header, contents)

@dataclass
class CtldTargetConfig:
  iqn: str
  lun: List[CtldTargetLunConfig]
  auth_group: str = "no-authentication"
  portal_group: str = "pg-targetd"

  def append_lun(self, new_lun: CtldTargetLunConfig):
    logging.debug(f"append_lun: {new_lun}")
    if any(l.id == new_lun.id for l in self.lun):
      raise BaseException(f"Trying to append lun that conflicts lun id: {new_lun.id}")

    self.lun.append(new_lun)

  def to_ctl_config(self):
    if self.iqn is None:
      raise BaseException("target iqn must be set")
    if self.auth_group is None:
      raise BaseException("target auth_group must be set")
    if self.portal_group is None:
      raise BaseException("target portal_group must be set")

    header = f"target {self.iqn}"

    contents = [
        f"auth-group {self.auth_group}",
        f"portal-group {self.portal_group}",
    ]

    for l in self.lun:
      contents.append(l.to_ctl_config())

    return compose_config(header, contents)

@dataclass
class CtldConfig:
  portal_group: CtldPortalGroupConfig
  target: List[CtldTargetConfig]

  def to_ctl_config(self):
    config = ""
    config += self.portal_group.to_ctl_config()
    config += "\n"

    for t in self.target:
      config += t.to_ctl_config()
      config += "\n"

    return config


def strict_load_yaml(yaml: str, loaded_type: Type[Any]):
    schema = class_schema(loaded_type)
    return schema().load(load(yaml, Loader=SafeLoader))

def dump_yaml(obj: Any, source_type: Type[Any]):
    schema = class_schema(source_type)
    return dump(schema().dump(obj))

def load_file(path="/etc/target/ctld.yaml"):
  with open(path, "r") as f:
    return strict_load_yaml(f, CtldConfig)

def check_file_exists(path="/etc/target/ctld.yaml"):
  return os.path.exists(path)

def check_file_permission(path="/etc/target/ctld.yaml"):
  if not (os.access(path, os.R_OK) and os.access(path, os.W_OK)):
    return False
    # raise BaseException(f"Config file path: {path} is either not readable or not writable")

  return True

def init_config(listen, iqn):
  portal_group = CtldPortalGroupConfig(listen=listen)
  target = CtldTargetConfig(iqn=iqn, lun=[])
  return CtldConfig(portal_group=portal_group,
                    target=[target])

def save_file(config: CtldConfig, path = "/etc/target/ctld.yaml"):
  with open(path, "w") as f:
    f.write(dump_yaml(config, CtldConfig))

def reload_ctld(config: CtldConfig, pidfile="/var/run/ctld.pid", confpath="/etc/ctl.conf"):
  with open(confpath, "w") as f:
    f.write(config.to_ctl_config())

  pid_str = open(pidfile, "r").read()
  os.kill(int(pid_str), SIGHUP)
