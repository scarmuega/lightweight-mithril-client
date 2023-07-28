//! Pre hex encoded StmTypes for testing.

/// A list of pre json hex encoded [MithrilStm:StmSig](type@mithril_stm::stm::StmSig)
pub fn single_signature<'a>() -> [&'a str; 3] {
    [
        "7b227369676d61223a5b3133302c3137372c31352c3232392c32342c3235312c3234372c3137312c3139362c32\
        31302c3134332c3131332c38362c3138392c39322c35362c3131322c33332c3139332c3231322c35342c3231342\
        c32382c3231362c3232372c3137332c3130302c3132372c3137382c34302c39382c38372c32392c3138312c3235\
        352c3131312c3135372c3232342c3233352c34362c3130302c3136392c3233322c3138392c3235322c38322c313\
        3392c33365d2c22696e6465786573223a5b302c312c332c342c362c382c392c31302c31312c31322c31342c3138\
        2c32312c32322c32332c32352c32362c32372c33302c33332c33342c33382c34312c34332c35302c35382c35392\
        c36302c36312c36322c36372c36392c37312c37332c37352c37362c37372c38312c38322c38332c38342c39302c\
        39312c39322c39332c39372c39385d2c227369676e65725f696e646578223a327d",
        "7b227369676d61223a5b3136362c3130352c39352c32382c31312c3139372c32352c31372c3132392c3231312c\
        3136312c35322c3231372c3232382c3136362c38342c37312c39342c3133312c3133312c32332c35302c3131342\
        c3138382c32322c3133372c3231342c37372c3234332c3233382c3136332c3130322c34392c36342c32332c3832\
        2c3139312c3235312c3132302c34312c3230352c3131302c3232352c3138342c38352c32342c382c3130325d2c2\
        2696e6465786573223a5b352c382c392c31322c31332c31352c32302c32312c32332c32352c32392c33312c3334\
        2c33362c33392c34302c34332c34342c34352c34382c35352c35372c36312c36362c36382c37312c37322c37332\
        c37342c37382c37392c38302c38322c38332c38382c39312c39322c39342c39352c39362c3130322c3130352c31\
        30362c3130382c3131302c3131322c3131332c3131352c3131372c3131392c3132322c3132332c3132352c31323\
        82c3132392c3133332c3133372c3133392c3134302c3134312c3134322c3134342c3134362c3134372c3134382c\
        3134392c3135312c3135322c3135342c3135392c3136302c3136312c3136322c3136332c3136342c3136362c313\
        6372c3136382c3137302c3137322c3137342c3137372c3137382c3137392c3138302c3138322c3138342c313837\
        2c3138382c3138392c3139312c3139332c3139352c3139372c3230302c3230322c3230352c3230362c3230382c3\
        230395d2c227369676e65725f696e646578223a307d",
        "7b227369676d61223a5b3133312c3133342c3235322c3138372c31352c3135362c352c3130352c31372c323532\
        2c3137372c3231382c3132372c3133342c36312c3235352c3232382c33332c3136382c33312c3131362c3131332\
        c3138302c3232362c3232392c32312c3137302c35392c322c3138332c3232322c38312c3235302c31332c313933\
        2c31332c3234362c3232392c3137302c3130352c3138352c3136342c38382c392c3136302c35322c3130332c323\
        15d2c22696e6465786573223a5b302c312c322c342c352c362c372c382c392c31322c31342c32342c32382c3239\
        2c33312c33332c33352c33362c33382c34302c34312c34322c34332c34372c34392c35302c35312c35322c35342\
        c35352c35362c35372c35382c35392c36302c36312c36322c36342c36362c36372c36382c36392c37312c37322c\
        37342c37362c37372c37382c37392c38302c38312c38322c38332c38342c38362c38392c39302c39312c39332c3\
        9352c39362c39372c39382c3130302c3130312c3130352c3130362c3130382c3130392c3131302c3131312c3131\
        322c3131332c3131382c3131392c3132302c3132312c3132322c3132332c3132342c3132352c3132362c3132372\
        c3132382c3133302c3133322c3133362c3134302c3134322c3134332c3134342c3134352c3134392c3135312c31\
        35342c3135362c3135372c3135382c3135392c3136302c3136312c3136322c3136332c3136342c3136362c31363\
        72c3136382c3136392c3137302c3137312c3137322c3137332c3137342c3137382c3137392c3138302c3138312c\
        3138322c3138332c3138342c3138352c3138362c3138392c3139302c3139312c3139322c3139332c3139352c313\
        9362c3139392c3230312c3230322c3230332c3230342c3230352c3230362c3230385d2c227369676e65725f696e\
        646578223a317d",
    ]
}

#[cfg(test)]
mod test {
    use super::*;
    use mithril_stm::stm::StmSig;
    use serde::{de::DeserializeOwned, Serialize};
    use std::any::type_name;

    use crate::crypto_helper::key_decode_hex;

    fn assert_encoded_are_still_matching_concrete_type<T: Serialize + DeserializeOwned>(
        encoded_types: &[&str],
    ) {
        let errors: Vec<String> = encoded_types
            .iter()
            .filter_map(|encoded_type| match key_decode_hex::<T>(encoded_type) {
                Ok(_) => None,
                Err(error_src) => {
                    let error = format!(
                        "> The encoded key does not match anymore the structure of the type: `{}`\
                        \n  * error: {error_src}\
                        \n  * encoded_string: {encoded_type}",
                        type_name::<T>()
                    );

                    Some(error)
                }
            })
            .collect();

        assert!(
            errors.is_empty(),
            "At least one of the encoded values could not be decoded:\n{}",
            errors.join("\n")
        );
    }

    #[test]
    fn assert_encoded_single_signatures_are_still_matching_concrete_type() {
        assert_encoded_are_still_matching_concrete_type::<StmSig>(&single_signature());
    }
}
