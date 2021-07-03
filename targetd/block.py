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
# Copyright 2012-2013, Andy Grover <agrover@redhat.com>
#
# Routines to export block devices over iscsi.

import logging
from targetd.backends import zfs
from targetd.backends import ctld
from targetd.main import TargetdError
from targetd.utils import ignored, name_check

MAX_LUN = 256

pool_modules = {"zfs": zfs}
target_name = ""
addresses = []
ctld_config = None

def pool_module(pool_name):
    for modname, mod in pool_modules.items():
        if mod.has_pool(pool_name):
            return mod
    raise TargetdError(TargetdError.INVALID_POOL, "Invalid pool (%s)" % pool_name)


def udev_path_module(udev_path):
    for modname, mod in pool_modules.items():
        if mod.has_udev_path(udev_path):
            return mod
    raise TargetdError(
        TargetdError.INVALID_POOL, "Pool not found by udev path (%s)" % udev_path
    )


def so_name_module(so_name):
    for modname, mod in pool_modules.items():
        if mod.has_so_name(so_name):
            return mod
    raise TargetdError(
        TargetdError.INVALID_POOL, "Pool not found by storage object (%s)" % so_name
    )


#
# config_dict must include block_pools and target_name or we blow up
#
def initialize(config_dict):
    pools = dict()
    pools["zfs"] = list(config_dict["zfs_block_pools"])

    global ctld_config

    if len(config_dict["portal_addresses"]) != 1:
        raise TargetdError(
            TargetdError.INVALID, "currently, only one portal_addresses is supported"
        )

    if not ctld.check_file_exists():
        ctld_config = ctld.init_config(
            listen=config_dict["portal_addresses"][0],
            iqn=config_dict["target_name"],
            )
        try:
            logging.debug("Initiate ctld config")
            ctld.save_file(ctld_config)
        except:
            raise TargetdError(
                TargetdError.INVALID, "Failed to save ctld init config"
            )
    else:
        if not ctld.check_file_permission():
            raise TargetdError(
                TargetdError.INVALID_POOL, "ctld config file is not readable or not writable"
            )

        logging.debug("Load ctld config")
        ctld_config = ctld.load_file()


    global target_name
    target_name = config_dict["target_name"]

    global addresses
    addresses = config_dict["portal_addresses"]

    # initialize and check both pools
    for modname, mod in pool_modules.items():
        mod.initialize(config_dict, pools[modname])

    return dict(
        vol_list=volumes,
        vol_create=create,
        vol_destroy=destroy,
        vol_copy=copy,
        vol_resize=resize,
        export_list=export_list,
        export_create=export_create,
        export_destroy=export_destroy,
        initiator_set_auth=initiator_set_auth,
        # initiator_list=initiator_list,
    )


def volumes(req, pool):
    return pool_module(pool).volumes(req, pool)


def check_vol_exists(req, pool, name):
    mod = pool_module(pool)
    if any(v["name"] == name for v in mod.volumes(req, pool)):
        return True
    return False


def create(req, pool, name, size):
    mod = pool_module(pool)
    # Check to ensure that we don't have a volume with this name already,
    # lvm/zfs will fail if we try to create a LV/dataset with a duplicate name
    if check_vol_exists(req, pool, name):
        raise TargetdError(TargetdError.NAME_CONFLICT, "Volume with that name exists")
    mod.create(req, pool, name, size)


def get_so_name(pool, volname):
    return pool_module(pool).get_so_name(pool, volname)


def destroy(req, pool, name):
    mod = pool_module(pool)
    if not check_vol_exists(req, pool, name):
        raise TargetdError(
            TargetdError.NOT_FOUND_VOLUME,
            "Volume %s not found in pool %s" % (name, pool),
        )

    udev_path = mod.get_dev_path(pool, name)
    found = False

    for target in ctld_config.target:
        for l in target.lun:
            if l.path != udev_path:
                continue
            found = True

    if found:
        raise TargetdError(
            TargetdError.VOLUME_MASKED,
            "Volume '%s' cannot be " "removed while exported" % name,
        )

    mod.destroy(req, pool, name)


def copy(req, pool, vol_orig, vol_new, size=None, timeout=10):
    mod = pool_module(pool)
    if not check_vol_exists(req, pool, vol_orig):
        raise TargetdError(
            TargetdError.NOT_FOUND_VOLUME,
            "Volume %s not found in pool %s" % (vol_orig, pool),
        )

    if size is not None:
        for v in mod.volumes(req, pool):
            if v["name"] == vol_orig and v["size"] >= size:
                raise TargetdError(
                    TargetdError.INVALID_ARGUMENT,
                    "Size %d need a larger than size in original volume %s in pool %s"
                    % (size, vol_orig, pool),
                )

    mod.copy(req, pool, vol_orig, vol_new, size, timeout)


def resize(req, pool, name, size):
    mod = pool_module(pool)
    if not check_vol_exists(req, pool, name):
        raise TargetdError(
            TargetdError.NOT_FOUND_VOLUME,
            "Volume %s not found in pool %s" % (name, pool),
        )

    for v in mod.volumes(req, pool):
        if v["name"] == name and v["size"] >= size:
            raise TargetdError(
                TargetdError.INVALID_ARGUMENT,
                "Size %d need a larger than size in original volume %s in pool %s"
                % (size, name, pool),
            )

    mod.resize(req, pool, name, size)


def export_list(req):
    exports = []
    for target in ctld_config.target:
        for l in target.lun:
            mod = udev_path_module(l.path)
            mlun_pool, mlun_name = mod.split_udev_path(l.path)
            vinfo = mod.vol_info(mod.dev2pool_name(mlun_pool), mlun_name)
            for initiator_wwn in l.initiator_wwns:
                exports.append(
                    dict(
                        initiator_wwn=initiator_wwn,
                        lun=l.id,
                        vol_name=mlun_name,
                        pool=mod.dev2pool_name(mlun_pool),
                        vol_uuid=vinfo.uuid,
                        vol_size=vinfo.size,
                    )
                )

    return exports


def export_create(req, pool, vol, initiator_wwn, lun):
    mod = pool_module(pool)
    udev_path = mod.get_dev_path(pool, vol)

    found = False
    for target in ctld_config.target:
        for l in target.lun:
            if l.path != udev_path:
                continue
            found = True

            l.initiator_wwns.append(initiator_wwn)

    if not found:
        vol_info = mod.vol_info(pool, vol)
        new_lun = ctld.CtldTargetLunConfig(
            id=lun,
            path=mod.get_dev_path(pool, vol),
            initiator_wwns=[initiator_wwn],
            blocksize=vol_info.volblocksize,)

        ctld_config.target[0].append_lun(new_lun)
    ctld.save_file(ctld_config)
    ctld.reload_ctld(ctld_config)


def export_destroy(req, pool, vol, initiator_wwn):
    mod = pool_module(pool)
    udev_path = mod.get_dev_path(pool, vol)

    found = False

    for target in ctld_config.target:
        for l in target.lun:
            if l.path != udev_path:
                continue
            found = True

            if initiator_wwn not in l.initiator_wwns:
                raise TargetdError(
                    TargetdError.NOT_FOUND_VOLUME_EXPORT,
                    "Volume '%s' found in ctld exports, but not found %s" % (vol, initiator_wwn),
                )

            if len(l.initiator_wwns) == 1:
                # No other initiator_wwn in lun, so remove whole lun
                target.lun.remove(l)
            else:
                l.initiator_wwns.remove(initiator_wwn)

    if not found:
        raise TargetdError(
            TargetdError.NOT_FOUND_VOLUME_EXPORT,
            "Volume '%s' not found in ctld exports" % (vol),
        )

    ctld.save_file(ctld_config)
    ctld.reload_ctld(ctld_config)


def initiator_set_auth(req, initiator_wwn, in_user, in_pass, out_user, out_pass):
    # TODO: re-implement if auth is needed
    pass

    # fm = FabricModule("iscsi")
    # t = Target(fm, target_name)
    # tpg = TPG(t, 1)
    # na = NodeACL(tpg, initiator_wwn)

    # if not in_user or not in_pass:
    #     # rtslib treats '' as its NULL value for these
    #     in_user = in_pass = ""

    # if not out_user or not out_pass:
    #     out_user = out_pass = ""

    # na.chap_userid = in_user
    # na.chap_password = in_pass

    # na.chap_mutual_userid = out_user
    # na.chap_mutual_password = out_pass



def block_pools(req):
    results = []

    for modname, mod in pool_modules.items():
        results += mod.block_pools(req)

    return results
