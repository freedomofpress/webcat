from grpc import insecure_channel, secure_channel
from struct import unpack

from google.protobuf.any_pb2 import Any 
from google.protobuf.duration_pb2 import Duration
from google.protobuf.timestamp_pb2 import Timestamp
from google.protobuf.field_mask_pb2 import FieldMask

import trillian_proto.trillian_admin_api_pb2 as trillian_admin
import trillian_proto.trillian_admin_api_pb2_grpc as trillian_admin_rpc

import trillian_proto.trillian_pb2 as trillian
import trillian_proto.trillian_pb2_grpc as trillian_rpc

import trillian_proto.trillian_log_api_pb2 as trillian_log
import trillian_proto.trillian_log_api_pb2_grpc as trillian_log_rpc

# See https://github.com/google/trillian/blob/master/types/logroot.go
# I refuse to add a TLS dep just for this, but this is an ugly hack :(
class LogRoot:
    def __init__(self, log_root) -> None:
        if len(log_root) < 3:
            raise Exception("log_root is too short.")

        UINT8 = 1
        UINT16 = 2
        UINT32 = 4
        UINT64 = 8

        cur = 0
        # version is uint16
        version_bytes = log_root[cur:cur+UINT16]
        version = unpack(">H", version_bytes)[0]
        cur += UINT16

        if version != trillian.LOG_ROOT_FORMAT_V1:
            raise Exception(f"log_root version is {version} instead of {trillian.LOG_ROOT_FORMAT_V1}.")

        self.version = version

        # tree_size is uint64
        tree_size_bytes = log_root[cur:cur+UINT64]
        self.tree_size = unpack(">Q", tree_size_bytes)[0]
        cur += UINT64

        # no need to unpack a single byte
        self.root_hash_length = log_root[cur]
        cur += UINT8
        
        if self.root_hash_length < 0 or self.root_hash_length > 128:
            raise Exception("Something went wrong in deserializing the LogRoot object. Probably a real TLS decoder is needed.")

        # sha256 is default
        self.root_hash = log_root[cur:cur+self.root_hash_length]
        cur += self.root_hash_length

        timestamp_nanos_bytes = log_root[cur:cur+UINT64]
        self.timestamp_nanos = unpack(">Q", timestamp_nanos_bytes)[0]
        cur += UINT64

        # it's deprecated, but it's there, bruh
        revision_bytes = log_root[cur:cur+UINT64]
        self.revision = unpack(">Q", revision_bytes)[0]
        cur += UINT64

        metadata_lenght_bytes = log_root[cur:cur+UINT16]
        self.metadata_length = unpack(">H", metadata_lenght_bytes)[0]
        cur += UINT16

        # here the end is specified on purpose to raise exceptions on parsing errors
        self.metadata = log_root[cur:cur+self.metadata_length]
    
    def to_dict(self):
        return dict(version=self.version,
                    tree_size=self.tree_size,
                    hash=self.root_hash.hex(),
                    timestamp=self.timestamp_nanos,
                    revision=self.revision,
                    metadata=self.metadata.hex())


class TrillianAdminApi:
    def __init__(self, host, port, secure=False, credentials=None) -> None:
        if not secure:
            self.channel = insecure_channel(f"{host}:{port}")
        else:
            if not credentials:
                raise Exception("Credentials are needed for a secure channel.")
            self.channel = secure_channel(f"{host}:{port}")
        
        self.stub = trillian_admin_rpc.TrillianAdminStub(self.channel)


    def create_tree(self, tree_id, tree_type=None, tree_state=None, display_name="", description="", max_root_duration=None) -> trillian.Tree:
        if not isinstance(tree_id, int):
            raise Exception("tree_id is not an integer.")

        if tree_type is None:
            tree_type = trillian.TreeType.LOG

        if tree_state is None:
            tree_state = trillian.TreeState.ACTIVE
        
        if tree_type not in trillian.TreeType.values():
            raise Exception("tree_type is invalid.")

        if tree_state not in trillian.TreeState.values():
            raise Exception("tree_state is invalid.")

        if len(display_name) > 20:
            raise Exception("display_name must be less than 20 characters.")

        if len(display_name) > 200:
            raise Exception("description must be less than 200 characters.")

        if max_root_duration is None:
            max_root_duration = Duration()
            max_root_duration.FromSeconds(0)

        tree = trillian.Tree(tree_id=tree_id, tree_type=tree_type, tree_state=tree_state, display_name=display_name, description=description, max_root_duration=max_root_duration)
        request = trillian_admin.CreateTreeRequest(tree=tree)
        response = self.stub.CreateTree(request)
        return response


    def delete_tree(self, tree_id) -> trillian.Tree:
        request = trillian_admin.DeleteTreeRequest(tree_id=tree_id)
        response = self.stub.DeleteTree(request)
        return response


    def get_tree(self, tree_id) -> trillian.Tree:
        request = trillian_admin.GetTreeRequest(tree_id=tree_id)
        response = self.stub.GetTree(request)
        return response


    def list_trees(self, show_deleted=False) -> trillian_admin.ListTreesResponse:
        request = trillian_admin.ListTreesRequest(show_deleted=show_deleted)
        response = self.stub.ListTrees(request)
        return response


    def undelete_tree(self, tree_id) -> trillian.Tree:
        request = trillian_admin.UndeleteTreeRequest(tree_id=tree_id)
        response = self.stub.UndeleteTree(request)
        return response


    def update_tree(self, tree_id=None, tree=None, update_mask=None) -> trillian.Tree:
        # TODO: document field mask usage
        # TODO: test
        if tree_id is None and tree is None:
            raise Exception("Either a tree_id or a Tree object must be provided")

        if tree_id is not None and tree is not None:
            raise Exception("Either supply a tree_id or a Tree object, not both.")

        if not tree:
            tree = self.get_tree(tree_id)

        if update_mask is None:
            raise Exception("An update_mask must be provided in order to update a tree.")

        if type(update_mask) is not FieldMask:
            raise Exception("update_mask must be a google.protobuf.FieldMask type.")

        request = trillian_admin.UpdateTree(tree=tree, update_mask=update_mask)
        response = self.stub.UpdateTree(request)
        return response


class TrillianApi:
    def __init__(self, host, port, tree_id, charge_to="", secure=False, credentials=None) -> None:
        if not secure:
            self.channel = insecure_channel(f"{host}:{port}")
        else:
            if not credentials:
                raise Exception("Credentials are needed for a secure channel.")
            self.channel = secure_channel(f"{host}:{port}")
        
        self.stub = trillian_log_rpc.TrillianLogStub(self.channel)
        # looks like tree_id becomes log_id depending on the API :/
        self.log_id = tree_id
        self.charge_to = trillian_log.ChargeTo(user=charge_to)


    def add_sequenced_leaves(self, leaves) -> trillian_log.AddSequencedLeavesResponse:
        raise Exception("Not implemented.")


    def get_consistency_proof(self, first_tree_size, second_tree_size) -> trillian_log.GetConsistencyProofResponse:
        request = trillian_log.GetConsistencyProofRequest(log_id=self.log_id, first_tree_size=first_tree_size, second_tree_size=second_tree_size, charge_to=self.charge_to)
        response = self.stub.GetConsistencyProof(request)
        return response


    def get_entry_and_proof(self, leaf_index, tree_size) -> trillian_log.GetEntryAndProofResponse:
        request = trillian_log.GetEntryAndProofRequest(log_id=self.log_id, leaf_index=leaf_index, tree_size=tree_size, charge_to=self.charge_to)
        response = self.stub.GetEntryAndProof(request)
        return response


    def get_inclusion_proof_by_hash(self, leaf_hash, tree_size, order_by_sequence=False) -> trillian_log.GetInclusionProofByHashResponse:
        request = trillian_log.GetInclusionProofByHashRequest(log_id=self.log_id, leaf_hash=leaf_hash, tree_size=tree_size, order_by_sequence=order_by_sequence, charge_to=self.charge_to)
        response = self.stub.GetInclusionProofByHash(request)
        return response


    def get_inclusion_proof(self, leaf_index, tree_size) -> trillian_log.GetInclusionProofResponse:
        request = trillian_log.GetInclusionProofRequest(log_id=self.log_id, leaf_index=leaf_index, tree_size=tree_size, charge_to=self.charge_to)
        response = self.stub.GetInclusionProof(request)
        return response


    def get_latest_signed_log_root(self, first_tree_size=0) -> trillian_log.GetLatestSignedLogRootResponse:
        request = trillian_log.GetLatestSignedLogRootRequest(log_id=self.log_id, first_tree_size=first_tree_size)
        response = self.stub.GetLatestSignedLogRoot(request)
        return response


    def get_leaves_by_range(self, start_index, count) -> trillian_log.GetLatestSignedLogRootResponse:
        raise Exception("Not implemented.")
        pass


    def init_log(self) -> trillian_log.InitLogResponse:
        # this has always to be called once after a new tree has been created
        request = trillian_log.InitLogRequest(log_id=self.log_id, charge_to=self.charge_to)
        response = self.stub.InitLog(request)
        return response


    def queue_leaf(self, leaf) -> trillian_log.QueueLeafResponse:
        if not isinstance(leaf, trillian_log.LogLeaf):
            raise Exception("leaf must be a LogLeaf object.")

        request = trillian_log.QueueLeafRequest(log_id=self.log_id, leaf=leaf, charge_to=self.charge_to)
        response = self.stub.QueueLeaf(request)
        return response


    def queue_leaf_raw(self, leaf):
        leafobj = trillian_log.LogLeaf(leaf_value=leaf)
        return self.queue_leaf(leafobj)