import pytest

from minisignxml.internal import utils


@pytest.mark.parametrize(
    "input,output",
    [
        (
            b"<parent><prev></prev> <remove></remove> <next></next></parent>",
            b"<parent><prev></prev>  <next></next></parent>",
        ),
        (b"<parent> <remove></remove> </parent>", b"<parent>  </parent>"),
    ],
)
def test_remove_element(input, output):
    tree = utils.deserialize_xml(input)
    element = tree.find("remove")
    utils.remove_preserving_whitespace(element)
    result = utils.serialize_xml(tree)
    assert result == output
