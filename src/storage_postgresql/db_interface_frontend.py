from typing import Any, Dict, List, NamedTuple, Optional, Set, Tuple, Union

from sqlalchemy import Column, func, select
from sqlalchemy.dialects.postgresql import JSONB

from helperFunctions.data_conversion import get_value_of_first_key
from helperFunctions.tag import TagColor
from helperFunctions.virtual_file_path import get_top_of_virtual_path
from objects.file import FileObject
from objects.firmware import Firmware
from storage_postgresql.db_interface_common import DbInterface
from storage_postgresql.query_conversion import build_generic_search_query, query_parent_firmware
from storage_postgresql.schema import AnalysisEntry, FileObjectEntry, FirmwareEntry, SearchCacheEntry
from web_interface.file_tree.file_tree import VirtualPathFileTree
from web_interface.file_tree.file_tree_node import FileTreeNode

MetaEntry = NamedTuple('MetaEntry', [('uid', str), ('hid', str), ('tags', dict), ('submission_date', int)])


class FrontEndDbInterface(DbInterface):

    def get_last_added_firmwares(self, limit: int = 10) -> List[MetaEntry]:
        with self.get_read_only_session() as session:
            query = select(FirmwareEntry).order_by(FirmwareEntry.submission_date.desc()).limit(limit)
            return [
                self._get_meta_for_entry(fw_entry)
                for fw_entry in session.execute(query).scalars()
            ]

    # --- HID ---

    def get_hid(self, uid, root_uid=None):  # FixMe? replace with direct query
        '''
        returns a human-readable identifier (hid) for a given uid
        returns an empty string if uid is not in Database
        '''
        hid = self._get_hid_firmware(uid)
        if hid is None:
            hid = self._get_hid_fo(uid, root_uid)
        if hid is None:
            return ''
        return hid

    def _get_hid_firmware(self, uid: str) -> Optional[str]:
        firmware = self.get_firmware(uid)
        if firmware is not None:
            part = '' if firmware.part in ['', None] else f' {firmware.part}'
            return f'{firmware.vendor} {firmware.device_name} -{part} {firmware.version} ({firmware.device_class})'
        return None

    def _get_hid_fo(self, uid, root_uid):
        fo = self.get_object(uid)
        if fo is None:
            return None
        return get_top_of_virtual_path(fo.get_virtual_paths_for_one_uid(root_uid)[0])

    # --- "nice list" ---

    def get_data_for_nice_list(self, uid_list: List[str], root_uid: str) -> List[dict]:
        with self.get_read_only_session() as session:
            query = (
                select(FileObjectEntry, AnalysisEntry)
                .select_from(FileObjectEntry)
                .join(AnalysisEntry, AnalysisEntry.uid == FileObjectEntry.uid)
                .filter(AnalysisEntry.plugin == 'file_type', FileObjectEntry.uid.in_(uid_list))
            )
            return [
                {
                    'uid': fo_entry.uid,
                    'files_included': fo_entry.get_included_uids(),
                    'size': fo_entry.size,
                    'file_name': fo_entry.file_name,
                    'mime-type': type_analysis.result['mime'] if type_analysis else 'file-type-plugin/not-run-yet',
                    'current_virtual_path': self._get_current_vfp(fo_entry.virtual_file_paths, root_uid)
                }
                for fo_entry, type_analysis in session.execute(query)
            ]

    @staticmethod
    def _get_current_vfp(vfp: Dict[str, List[str]], root_uid: str) -> List[str]:
        return vfp[root_uid] if root_uid in vfp else get_value_of_first_key(vfp)

    # FixMe: not needed?
    def get_mime_type(self, uid: str) -> str:
        file_type_analysis = self.get_analysis(uid, 'file_type')
        if not file_type_analysis or 'mime' not in file_type_analysis.result:
            return 'file-type-plugin/not-run-yet'
        return file_type_analysis.result['mime']

    # --- misc. ---

    def get_firmware_attribute_list(self, attribute: Column) -> List[Any]:
        '''Get all distinct values of an attribute (e.g. all different vendors)'''
        with self.get_read_only_session() as session:
            query = select(attribute).filter(attribute.isnot(None)).distinct()
            return sorted(session.execute(query).scalars())

    def get_device_class_list(self):
        return self.get_firmware_attribute_list(FirmwareEntry.device_class)

    def get_vendor_list(self):
        return self.get_firmware_attribute_list(FirmwareEntry.vendor)

    def get_device_name_dict(self):
        device_name_dict = {}
        with self.get_read_only_session() as session:
            query = select(FirmwareEntry.device_class, FirmwareEntry.vendor, FirmwareEntry.device_name)
            for device_class, vendor, device_name in session.execute(query):
                device_name_dict.setdefault(device_class, {}).setdefault(vendor, []).append(device_name)
        return device_name_dict

    def get_other_versions_of_firmware(self, firmware: Firmware) -> List[Tuple[str, str]]:
        if not isinstance(firmware, Firmware):
            return []
        with self.get_read_only_session() as session:
            query = (
                select(FirmwareEntry.uid, FirmwareEntry.version)
                .filter(
                    FirmwareEntry.vendor == firmware.vendor,
                    FirmwareEntry.device_name == firmware.device_name,
                    FirmwareEntry.device_part == firmware.part,
                    FirmwareEntry.uid != firmware.uid
                )
                .order_by(FirmwareEntry.version.asc())
            )
            return list(session.execute(query))

    def get_latest_comments(self, limit=10):
        with self.get_read_only_session() as session:
            subquery = select(func.jsonb_array_elements(FileObjectEntry.comments)).subquery()
            query = select(subquery).order_by(subquery.c.jsonb_array_elements.cast(JSONB)['time'].desc())
            return list(session.execute(query.limit(limit)).scalars())

    def create_analysis_structure(self):
        pass  # ToDo FixMe ???

    # --- generic search ---

    def generic_search(self, search_dict: dict, skip: int = 0, limit: int = 0,
                       only_fo_parent_firmware: bool = False, inverted: bool = False, as_meta: bool = False):
        with self.get_read_only_session() as session:
            query = build_generic_search_query(search_dict, only_fo_parent_firmware, inverted)

            if skip:
                query = query.offset(skip)
            if limit:
                query = query.limit(limit)

            results = session.execute(query).scalars()

            if as_meta:
                return [self._get_meta_for_entry(element) for element in results]
            return [element.uid for element in results]

    def _get_meta_for_entry(self, entry: Union[FirmwareEntry, FileObjectEntry]):
        if isinstance(entry, FirmwareEntry):
            hid = self._get_hid_for_fw_entry(entry)
            tags = {tag: 'secondary' for tag in entry.firmware_tags}
            submission_date = entry.submission_date
        else:  # FileObjectEntry
            hid = self._get_one_virtual_path(entry)
            tags = {}
            submission_date = 0
        tags = {**tags, self._get_unpacker_name(entry): TagColor.LIGHT_BLUE}
        # ToDo: use NamedTuple Attributes in Template instead of indices
        return MetaEntry(entry.uid, hid, tags, submission_date)

    @staticmethod
    def _get_hid_for_fw_entry(entry: FirmwareEntry) -> str:
        part = '' if entry.device_part == '' else f' {entry.device_part}'
        return f'{entry.vendor} {entry.device_name} -{part} {entry.version} ({entry.device_class})'

    @staticmethod
    def _get_one_virtual_path(fo_entry: FileObjectEntry) -> str:
        return list(fo_entry.virtual_file_paths.values())[0][0]

    def _get_unpacker_name(self, fw_entry: FirmwareEntry) -> str:
        unpacker_analysis = self.get_analysis(fw_entry.uid, 'unpacker')
        if unpacker_analysis is None:
            return 'NOP'
        return unpacker_analysis.result['plugin_used']

    def get_number_of_total_matches(self, search_dict: dict, only_parent_firmwares: bool, inverted: bool) -> int:
        if search_dict == {}:
            return self.get_firmware_number()

        if not only_parent_firmwares:
            return self.get_file_object_number(search_dict)

        with self.get_read_only_session() as session:
            query = query_parent_firmware(search_dict, inverted=inverted, count=True)
            return session.execute(query).scalar()

    # --- file tree

    def generate_file_tree_nodes_for_uid_list(
            self, uid_list: List[str], root_uid: str,
            parent_uid: Optional[str], whitelist: Optional[List[str]] = None
    ):
        fo_dict = {fo.uid: fo for fo in self.get_objects_by_uid_list(uid_list, analysis_filter=['file_type'])}
        for uid in uid_list:
            for node in self.generate_file_tree_level(uid, root_uid, parent_uid, whitelist, fo_dict.get(uid, None)):
                yield node

    def generate_file_tree_level(
            self, uid: str, root_uid: str,
            parent_uid: Optional[str] = None, whitelist: Optional[List[str]] = None, fo: Optional[FileObject] = None
    ):
        if fo is None:
            fo = self.get_object(uid)
        try:
            fo_data = self._convert_fo_to_fo_data(fo)
            for node in VirtualPathFileTree(root_uid, parent_uid, fo_data, whitelist).get_file_tree_nodes():
                yield node
        except (KeyError, TypeError):  # the file has not been analyzed yet
            yield FileTreeNode(uid, root_uid, not_analyzed=True, name=f'{uid} (not analyzed yet)')

    @staticmethod
    def _convert_fo_to_fo_data(fo: FileObject) -> dict:
        # ToDo: remove this and change VirtualPathFileTree to work with file objects or make more efficient DB query
        return {
            '_id': fo.uid,
            'file_name': fo.file_name,
            'files_included': fo.files_included,
            'processed_analysis': {'file_type': {'mime': fo.processed_analysis['file_type']['mime']}},
            'size': fo.size,
            'virtual_file_path': fo.virtual_file_path,
        }

    # --- REST ---

    def rest_get_firmware_uids(self, offset: int, limit: int, query: dict = None, recursive=False, inverted=False):
        if recursive:
            return self.generic_search(query, skip=offset, limit=limit, only_fo_parent_firmware=True, inverted=inverted)
        with self.get_read_only_session() as session:
            db_query = select(FirmwareEntry.uid)
            if query:
                db_query = db_query.filter_by(**query)
            return list(session.execute(db_query.offset(offset).limit(limit)).scalars())

    def rest_get_file_object_uids(self, offset: Optional[int], limit: Optional[int], query=None) -> List[str]:
        if query:
            return self.generic_search(query, skip=offset, limit=limit)
        with self.get_read_only_session() as session:
            db_query = select(FileObjectEntry.uid).offset(offset).limit(limit)
            return list(session.execute(db_query).scalars())

    # --- missing files/analyses ---

    def find_missing_files(self):
        # FixMe: This should be impossible now -> Remove?
        return {}

    def find_orphaned_objects(self) -> Dict[str, List[str]]:
        # FixMe: This should be impossible now -> Remove?
        return {}

    def find_missing_analyses(self) -> Dict[str, Set[str]]:
        # FixMe? Query could probably be accomplished more efficiently with left outer join (either that or the RAM could go up in flames)
        missing_analyses = {}
        with self.get_read_only_session() as session:
            fw_query = self._query_all_plugins_of_object(FileObjectEntry.is_firmware.is_(True))
            for fw_uid, fw_plugin_list in session.execute(fw_query):
                fo_query = self._query_all_plugins_of_object(FileObjectEntry.root_firmware.any(uid=fw_uid))
                for fo_uid, fo_plugin_list in session.execute(fo_query):
                    missing_plugins = set(fw_plugin_list) - set(fo_plugin_list)
                    if missing_plugins:
                        missing_analyses[fo_uid] = missing_plugins
        return missing_analyses

    @staticmethod
    def _query_all_plugins_of_object(query_filter):
        return (
            # array_agg() aggregates different values of field into array
            select(AnalysisEntry.uid, func.array_agg(AnalysisEntry.plugin))
            .join(FileObjectEntry, AnalysisEntry.uid == FileObjectEntry.uid)
            .filter(query_filter)
            .group_by(AnalysisEntry.uid)
        )

    def find_failed_analyses(self) -> Dict[str, List[str]]:
        result = {}
        with self.get_read_only_session() as session:
            query = (
                select(AnalysisEntry.uid, AnalysisEntry.plugin)
                .filter(AnalysisEntry.result.has_key('failed'))
            )
            for fo_uid, plugin in session.execute(query):
                result.setdefault(plugin, set()).add(fo_uid)
        return result

    # --- search cache ---

    def get_query_from_cache(self, query_id: str) -> Optional[dict]:
        with self.get_read_only_session() as session:
            entry = session.get(SearchCacheEntry, query_id)
            if entry is None:
                return None
            # FixMe? for backwards compatibility. replace with NamedTuple/etc.?
            return {'search_query': entry.data, 'query_title': entry.title}