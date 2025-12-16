from enum import Enum
from typing import Any, Dict, List, Optional


class Tag:
    name: str
    description: Optional[str]
    url: Optional[str]

    def __init__(self, name: str, description: Optional[str] = None, url: Optional[str] = None):
        self.name = name
        self.description = description
        self.url = url


class TagEnum(Tag, Enum):
    """
    Enum to organize Tag documentation used by Routers, OpenAPI and Swagger.

    You can create tags following the example bellow:

    >>> class Tags(TagEnum):
    ...     TAG_1 = Tag(
    ...         name="Tag One",
    ...         description="My custom Tag One",
    ...         url="https://tags.staging.vrff.io/",
    ...     )
    ...     TAG_2 = Tag(name="Tag Two", description="My custom Tag Two")

    Once a Tag is defined, it can be injected into Routers to improve Swagger readability:

    >>> my_router = APIRouter(tags=[Tags.TAG_1])
    """

    def __init__(self, *args, **kwargs) -> None:
        # pylint: disable=super-init-not-called
        assert len(args) == 1, "only_one_tag_allowed"
        assert len(kwargs) == 0, "no_extra_parameters_allowed"
        assert isinstance(args[0], Tag), "only_tag_allowed"

        self._value_ = args[0].name
        self._detail_ = args[0]

    @property
    def detail(self) -> Tag:
        """The tag detail of the Enum member."""
        return self._detail_

    @classmethod
    def get_docs(cls) -> List[Dict[str, Any]]:
        return [cls._get_tag_description(item.detail) for item in cls]

    @staticmethod
    def _get_tag_description(tag: Tag) -> Dict[str, Any]:
        result: Dict[str, Any] = {"name": tag.name, "description": tag.description}

        if tag.url:
            result["externalDocs"] = {"url": tag.url}

        return result
