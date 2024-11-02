from ducopy.rest.apikeygenerator import ApiKeyGenerator


def test_transform_char() -> None:
    generator = ApiKeyGenerator()
    transformed_char = generator.transform_char("A", "B")
    assert isinstance(transformed_char, str)
    assert len(transformed_char) == 1


def test_generate_api_key() -> None:
    generator = ApiKeyGenerator()
    api_key = generator.generate_api_key("MOCKSERIAL123456", "00:00:00:00:00:00", 1730471603)
    assert len(api_key) == 64
    assert isinstance(api_key, str)
