# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

from .OntologyOntIdAttribute import OntologyOntIdAttribute

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class OntologyOntIdAddAttributes(p.MessageType):

    def __init__(
        self,
        ont_id: str = None,
        public_key: bytes = None,
        ont_id_attributes: List[OntologyOntIdAttribute] = None,
    ) -> None:
        self.ont_id = ont_id
        self.public_key = public_key
        self.ont_id_attributes = ont_id_attributes if ont_id_attributes is not None else []

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('ont_id', p.UnicodeType, 0),
            2: ('public_key', p.BytesType, 0),
            3: ('ont_id_attributes', OntologyOntIdAttribute, p.FLAG_REPEATED),
        }
