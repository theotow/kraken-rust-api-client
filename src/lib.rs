extern crate base64;
extern crate chrono;
extern crate hmac;
extern crate reqwest;
extern crate serde;
extern crate serde_json;
extern crate sha2;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate hyper;

pub mod kraken {
    use base64;
    use hmac::{Hmac, Mac};
    use reqwest;
    use reqwest::header::HeaderMap;
    use serde_json;
    use sha2::Digest;
    use sha2::Sha256;
    use sha2::Sha512;
    use std::collections::HashMap;
    use std::error::{self};
    use std::fmt;
    use std::io;
    use std::str;
    use std::string::String;
    use std::time::{SystemTime, UNIX_EPOCH};
    header! { (ApiKey, "API-Key") => [String] }
    header! { (ApiSign, "API-Sign") => [String] }

    pub static API_BASE: &str = "https://api.kraken.com";
    pub static API_VERSION: u8 = 0;

    pub enum ApiType {
        Public,
        Private,
    }

    #[derive(Debug)]
    pub enum Error {
        /// The API returned an error.
        Api(u32, String),
        /// An error occured when decoding JSON from the API.
        Json(serde_json::error::Error),
        /// An error occured with the network.
        Io(io::Error),
        /// An HTTP error occured with the webserver.
        Http(reqwest::Error),
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct ResultTime {
        pub rfc1123: String,
        pub unixtime: i64,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    pub struct ResultAssets {
        pub aclass: String,
        pub altname: String,
        pub decimals: i64,
        pub display_decimals: i64,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    pub struct ResultAssetPairs {
        pub aclass_base: String,
        pub altname: String,
        pub base: String,
        pub aclass_quote: String,
        pub quote: String,
        pub lot: String,
        pub pair_decimals: i64,
        pub lot_decimals: i64,
        pub lot_multiplier: i64,
        pub leverage_buy: Vec<i64>,
        pub leverage_sell: Vec<i64>,
        pub fees: Vec<Vec<f32>>,
        pub fees_maker: Option<Vec<Vec<f32>>>,
        pub fee_volume_currency: String,
        pub margin_call: i64,
        pub margin_stop: i64,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    pub struct ResultTicker {
        pub a: Vec<String>,
        pub b: Vec<String>,
        pub c: Vec<String>,
        pub v: Vec<String>,
        pub p: Vec<String>,
        pub t: Vec<i64>,
        pub l: Vec<String>,
        pub h: Vec<String>,
        pub o: String,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    pub struct ResultSpreadTimeAskBid(pub i64, pub String, pub String);

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    pub struct ResultSpread {
        pub data: Vec<ResultSpreadTimeAskBid>,
        pub last: i64,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    pub struct ResultTradesEntry(
        pub String,
        pub String,
        pub f64,
        pub String,
        pub String,
        pub String,
    );

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    pub struct ResultTrades {
        pub data: Vec<ResultTradesEntry>,
        pub last: String,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    pub struct ResultDepthEntry(pub String, pub String, pub i64);

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    pub struct ResultDepth {
        pub asks: Vec<ResultDepthEntry>,
        pub bids: Vec<ResultDepthEntry>,
    }

    pub struct SignResult {
        pub hash: String,
        pub map: HashMap<String, String>,
    }

    pub type ResultBalance = HashMap<String, String>;

    impl From<serde_json::error::Error> for Error {
        fn from(err: serde_json::error::Error) -> Self {
            Error::Json(err)
        }
    }

    impl From<reqwest::Error> for Error {
        fn from(err: reqwest::Error) -> Self {
            Error::Http(err)
        }
    }

    impl error::Error for Error {
        fn description(&self) -> &str {
            match *self {
                Error::Api(_, ref msg) => msg,
                Error::Json(ref err) => err.description(),
                Error::Io(ref err) => err.description(),
                Error::Http(ref err) => err.description(),
            }
        }

        fn cause(&self) -> Option<&dyn error::Error> {
            match *self {
                Error::Api(_, _) => None,
                Error::Json(ref err) => Some(err),
                Error::Io(ref err) => Some(err),
                Error::Http(ref err) => Some(err),
            }
        }
    }

    impl fmt::Display for Error {
        fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
            fmt.write_str(&self.to_string())
        }
    }

    pub struct Kraken {
        secret: String,
        key: String,
        client: reqwest::Client,
    }

    pub type KrakenResult = Result<serde_json::Value, Error>;
    pub type SimpleMap<T> = HashMap<String, T>;

    pub fn new(secret: String, key: String) -> Kraken {
        Kraken {
            secret,
            key,
            client: reqwest::Client::new(),
        }
    }

    impl Kraken {
        pub fn get_config(&self) -> String {
            format!("{}, {}", self.secret, self.key)
        }

        pub fn time(&self) -> Result<ResultTime, Error> {
            let url = get_api_url(&String::from("Time"), API_VERSION, ApiType::Public);
            let build = self.client.get(url);
            let res = process_request(build)?;
            let result_data: ResultTime = serde_json::from_value(res)?;
            Ok(result_data)
        }

        pub fn assets(&self) -> Result<SimpleMap<ResultAssets>, Error> {
            let url = get_api_url(&String::from("Assets"), API_VERSION, ApiType::Public);
            let build = self.client.get(url);
            let res = process_request(build);
            if res.is_ok() {
                // remap hashmap
                let result_data: serde_json::Value = serde_json::from_value(res.unwrap())?;
                let obj = result_data.as_object().unwrap();
                let mut obj_new: SimpleMap<ResultAssets> = HashMap::new();
                obj.keys().for_each(|s: &String| {
                    let v = obj.get(s).unwrap().to_owned();
                    let k = s.to_owned();
                    let v_p = serde_json::from_value(v).unwrap();
                    obj_new.insert(k, v_p);
                });
                Ok(obj_new)
            } else {
                Err(res.unwrap_err())
            }
        }

        pub fn asset_pairs(&self) -> Result<SimpleMap<ResultAssetPairs>, Error> {
            let url = get_api_url(&String::from("AssetPairs"), API_VERSION, ApiType::Public);
            let build = self.client.get(url);
            let res = process_request(build)?;
            // remap hashmap
            let result_data: serde_json::Value = serde_json::from_value(res)?;
            let obj = result_data.as_object().unwrap();
            let mut obj_new: SimpleMap<ResultAssetPairs> = HashMap::new();
            obj.keys().for_each(|s: &String| {
                let v = obj.get(s).unwrap().to_owned();
                let k = s.to_owned();
                let v_p = serde_json::from_value(v).unwrap();
                obj_new.insert(k, v_p);
            });
            Ok(obj_new)
        }

        pub fn ticker(&self, pairs: Vec<String>) -> Result<SimpleMap<ResultTicker>, Error> {
            let mut url = get_api_url(&String::from("Ticker"), API_VERSION, ApiType::Public);
            url.query_pairs_mut().append_pair("pair", &pairs.join(","));
            let build = self.client.get(url);
            let res = process_request(build)?;
            // remap hashmap
            let result_data: serde_json::Value = serde_json::from_value(res)?;
            let obj = result_data.as_object().unwrap();
            let obj_new: SimpleMap<ResultTicker> = HashMap::new();
            let export_obj =
                obj.iter()
                    .fold(obj_new, |mut acc, (k, v)| -> SimpleMap<ResultTicker> {
                        let v_p: Result<ResultTicker, serde_json::Error> =
                            serde_json::from_value(v.clone());
                        acc.insert(k.to_string(), v_p.unwrap()); // TODO: fix unsafe unwrap
                        acc
                    });
            Ok(export_obj)
        }

        pub fn spread(&self, pair: String) -> Result<ResultSpread, Error> {
            let mut url = get_api_url(&String::from("Spread"), API_VERSION, ApiType::Public);
            url.query_pairs_mut().append_pair("pair", &pair);
            let build = self.client.get(url);
            let res = process_request(build)?;
            let result_data: serde_json::Value = serde_json::from_value(res)?;
            let default = serde_json::Value::from("{}");
            let data: Vec<ResultSpreadTimeAskBid> =
                serde_json::from_value(result_data.get(pair).unwrap_or(&default).to_owned())?;
            let last: i64 =
                serde_json::from_value(result_data.get("last").unwrap_or(&default).to_owned())?;
            Ok(ResultSpread { data, last })
        }

        pub fn trades(&self, pair: String, since: Option<String>) -> Result<ResultTrades, Error> {
            let mut url = get_api_url(&String::from("Trades"), API_VERSION, ApiType::Public);
            url.query_pairs_mut().append_pair("pair", &pair);
            if let Some(sin) = since {
                url.query_pairs_mut().append_pair("since", &sin);
            }
            let build = self.client.get(url);
            let res = process_request(build)?;
            let result_data: serde_json::Value = serde_json::from_value(res)?;
            let default = serde_json::Value::from("{}");
            let field_data = result_data.get(pair).unwrap_or(&default); // safe unwrap
            let data: Vec<ResultTradesEntry> = serde_json::from_value(field_data.to_owned())?;
            let last: String =
                serde_json::from_value(result_data.get("last").unwrap_or(&default).to_owned())?;
            Ok(ResultTrades { data, last })
        }
        pub fn depth(&self, pair: String, count: Option<String>) -> Result<ResultDepth, Error> {
            let mut url = get_api_url(&String::from("Depth"), API_VERSION, ApiType::Public);
            url.query_pairs_mut().append_pair("pair", &pair);
            if let Some(cnt) = count {
                url.query_pairs_mut().append_pair("count", &cnt);
            }
            let build = self.client.get(url);
            let res: serde_json::Value = process_request(build)?;
            let result_data: serde_json::Value = serde_json::from_value(res)?;
            let default = serde_json::Value::from("{}");
            let asks_field = result_data
                .get(&pair)
                .unwrap_or(&default)
                .get("asks")
                .unwrap_or(&default); // safe unwrap
            let bids_field = result_data
                .get(&pair)
                .unwrap_or(&default)
                .get("bids")
                .unwrap_or(&default); // safe unwrap
            let asks: Vec<ResultDepthEntry> = serde_json::from_value(asks_field.to_owned())?;
            let bids: Vec<ResultDepthEntry> = serde_json::from_value(bids_field.to_owned())?;
            Ok(ResultDepth { bids, asks })
        }

        pub fn balance(&self) -> Result<ResultBalance, Error> {
            let params: HashMap<String, String> = HashMap::new();
            let res = self.private_request(String::from("Balance"), params)?;
            let output: ResultBalance = serde_json::from_value(res)?;
            Ok(output)
        }

        pub fn private_request(
            &self,
            path: String,
            map: HashMap<String, String>,
        ) -> Result<serde_json::Value, Error> {
            let url = get_api_url(&path, API_VERSION, ApiType::Private);
            let mut headers = HeaderMap::new();
            let secret = base_64(self.secret.clone());
            let res = create_sign(url.path().to_string().into_bytes(), secret, &map);
            headers.insert("API-Key", self.key.parse().unwrap());
            headers.insert("API-Sign", res.hash.parse().unwrap());
            let build = self.client.post(url).headers(headers).form(&res.map);
            let res = process_request(build)?;
            Ok(res)
        }
    }

    pub fn process_request(builder: reqwest::RequestBuilder) -> KrakenResult {
        let mut result = builder.send()?;

        let json_result = match serde_json::from_reader(&mut result)? {
            serde_json::Value::Object(obj) => obj,
            _ => return Err(Error::Api(0, "Invalid response".to_string())),
        };

        if !json_result.contains_key("result") {
            let error = format!("{:#?}", json_result);
            return Err(Error::Api(500, error));
        }
        Ok(json_result.get("result").unwrap().to_owned())
    }

    pub fn get_api_url_string(api: &str, version: u8, atype: ApiType) -> String {
        let type_string = match atype {
            ApiType::Private => String::from("private"),
            ApiType::Public => String::from("public"),
        };
        format!("{}/{}/{}/{}", API_BASE, version, type_string, api)
    }

    pub fn get_api_url(api: &str, version: u8, atype: ApiType) -> reqwest::Url {
        reqwest::Url::parse(&get_api_url_string(api, version, atype)).unwrap()
    }

    pub fn base_64(input: String) -> Vec<u8> {
        base64::decode(&input).unwrap()
    }

    pub fn sha256(input: String) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.input(input.as_bytes());
        hasher.result().to_vec()
    }

    pub fn sha512(input: Vec<u8>, secret: Vec<u8>) -> Vec<u8> {
        let mut mac = Hmac::<Sha512>::new(&secret).unwrap();
        mac.input(&input);
        mac.result().code().to_vec()
    }

    pub fn create_sign(
        mut path: Vec<u8>,
        secret: Vec<u8>,
        hash_map: &HashMap<String, String>,
    ) -> SignResult {
        let timestamp = get_time().to_string();
        let mut should_insert = false;
        let mut hash_map_clone = hash_map.clone();
        let time: String = match hash_map_clone.get("nonce") {
            Some(val) => val.to_string(),
            None => {
                should_insert = true;
                timestamp.clone()
            }
        };
        if should_insert {
            hash_map_clone.insert("nonce".to_string(), timestamp);
        }
        let mut query = String::from("");
        query.push_str(&time);
        query.push_str(&map_to_formdata(&hash_map_clone));
        let mut sha256_res = sha256(query);
        let mut to_hash = vec![];
        to_hash.append(&mut path);
        to_hash.append(&mut sha256_res);
        let sha512_res = sha512(to_hash, secret);
        SignResult {
            hash: base64::encode(&sha512_res),
            map: hash_map_clone,
        }
    }

    pub fn map_to_formdata(map: &HashMap<String, String>) -> String {
        let mut res: String = map
            .iter()
            .map(|(k, v)| -> String { format!("{}={}", k, v) })
            .fold(String::from(""), |mut acc, val| {
                acc.push_str(&val);
                acc.push_str(&"&".to_string());
                acc
            });
        if !res.is_empty() {
            let index = res.len() - 1;
            res.remove(index);
        }
        res
    }

    pub fn get_time() -> u64 {
        let start = SystemTime::now();
        let since_the_epoch = start.duration_since(UNIX_EPOCH).unwrap();
        since_the_epoch.as_secs() * 1000000000
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;
    use std::collections::HashMap;
    use std::env;

    fn get_test_instance() -> kraken::Kraken {
        kraken::new(
            env::var("KRAKEN_SECRET").unwrap_or_else(|_| "".to_string()),
            env::var("KRAKEN_KEY").unwrap_or_else(|_| "".to_string()),
        )
    }

    #[test]
    fn stores_config() {
        let instance = kraken::new("secret".to_string(), "key".to_string());
        assert_eq!(String::from("secret, key"), instance.get_config());
    }

    #[test]
    fn builds_api_url() {
        let res = kraken::get_api_url_string("Message", 10, kraken::ApiType::Public);
        assert_eq!(
            String::from("https://api.kraken.com/10/public/Message"),
            res
        )
    }

    #[test]
    fn can_request_time() {
        let res = get_test_instance().time().unwrap();
        let target = 1536050055;
        assert_eq!(res.unixtime > target, true);
        assert_eq!(
            DateTime::parse_from_str(&res.rfc1123, "%a, %d %b %y %H:%M:%S %z")
                .unwrap()
                .timestamp()
                > target,
            true
        );
    }

    #[test]
    fn can_request_assets() {
        let res = get_test_instance().assets().unwrap();
        assert_eq!(
            res["XXBT"],
            kraken::ResultAssets {
                aclass: String::from("currency"),
                altname: String::from("XBT"),
                display_decimals: 5,
                decimals: 10,
            }
        );
    }

    #[test]
    fn can_request_asset_pairs() {
        let res = get_test_instance().asset_pairs().unwrap();
        assert_eq!(
            res["XREPXETH"],
            kraken::ResultAssetPairs {
                aclass_base: String::from("currency"),
                altname: String::from("REPETH"),
                base: String::from("XREP"),
                aclass_quote: String::from("currency"),
                quote: String::from("XETH"),
                lot: String::from("unit"),
                pair_decimals: 5,
                lot_decimals: 8,
                lot_multiplier: 1,
                leverage_buy: vec![2],
                leverage_sell: vec![2],
                fees: vec![
                    vec![0.00, 0.26],
                    vec![50000.0, 0.24],
                    vec![100000.0, 0.22],
                    vec![250000.0, 0.2],
                    vec![500000.0, 0.18],
                    vec![1000000.0, 0.16],
                    vec![2500000.0, 0.14],
                    vec![5000000.0, 0.12],
                    vec![10000000.0, 0.1]
                ],
                fees_maker: Some(vec![
                    vec![0.00, 0.16],
                    vec![50000.0, 0.14],
                    vec![100000.0, 0.12],
                    vec![250000.0, 0.1],
                    vec![500000.0, 0.08],
                    vec![1000000.0, 0.06],
                    vec![2500000.0, 0.04],
                    vec![5000000.0, 0.02],
                    vec![10000000.0, 0.0]
                ]),
                fee_volume_currency: String::from("ZUSD"),
                margin_call: 80,
                margin_stop: 40,
            }
        )
    }

    #[test]
    fn can_request_ticker() {
        let res = get_test_instance()
            .ticker(vec![String::from("BCHEUR"), String::from("BCHUSD")])
            .unwrap();
        assert_eq!(res.len(), 2);
        assert_eq!(res["BCHUSD"].h.len(), 2);
        assert_eq!(res["BCHUSD"].l.len(), 2);
        assert_eq!(res["BCHUSD"].t.len(), 2);
        assert_eq!(res["BCHUSD"].p.len(), 2);
        assert_eq!(res["BCHUSD"].c.len(), 2);
        assert_eq!(res["BCHUSD"].b.len(), 3);
        assert_eq!(res["BCHUSD"].a.len(), 3);
    }

    #[test]
    fn can_request_spread() {
        let res = get_test_instance().spread(String::from("BCHEUR")).unwrap();
        assert_eq!(res.last > 1536218176, true);
        assert_eq!(res.data.len() > 1, true);
    }

    #[test]
    fn can_request_trades() {
        let instance = get_test_instance();
        let res = instance.trades(String::from("BCHEUR"), None).unwrap();
        assert_eq!(res.data.len() > 10, true);
        let res1 = instance
            .trades(
                String::from("BCHEUR"),
                Some(String::from("2501609926936199446")),
            )
            .unwrap();
        assert_eq!(res1.data.is_empty(), true);
    }

    #[test]
    fn can_request_depth() {
        let instance = get_test_instance();
        let res = instance.depth(String::from("BCHEUR"), None).unwrap();
        assert_eq!(res.asks.len() > 1, true);
        assert_eq!(res.bids.len() > 1, true);
        let res1 = instance
            .depth(String::from("BCHEUR"), Some(String::from("1")))
            .unwrap();
        assert_eq!(res1.asks.len() == 1, true);
        assert_eq!(res1.bids.len() == 1, true);
    }

    #[test]
    fn can_request_calc_crypto() {
        let base_64 = kraken::base_64(String::from("aaa"));
        let sha_256 = kraken::sha256(String::from("bbb"));
        let sha_512 = kraken::sha512(String::from("ccc").into_bytes(), base_64.clone());

        assert_eq!(base_64, vec![105, 166]);
        assert_eq!(
            sha_256,
            vec![
                62, 116, 75, 157, 195, 147, 137, 186, 240, 197, 160, 102, 5, 137, 184, 64, 47, 61,
                187, 73, 184, 155, 62, 117, 242, 201, 53, 88, 82, 163, 198, 119
            ]
        );
        assert_eq!(
            sha_512,
            vec![
                128, 176, 49, 74, 23, 137, 186, 64, 12, 84, 246, 44, 29, 157, 230, 76, 110, 195,
                235, 85, 179, 93, 13, 71, 51, 110, 214, 77, 13, 121, 248, 168, 227, 214, 91, 92,
                207, 226, 140, 0, 185, 33, 145, 193, 128, 84, 86, 184, 41, 234, 245, 3, 85, 240,
                179, 196, 38, 43, 51, 62, 240, 34, 235, 28
            ]
        );

        let path = String::from("/private/Balance").into_bytes();
        let mut map: HashMap<String, String> = HashMap::new();
        map.insert("nonce".to_string(), "1234".to_string());
        let res = kraken::create_sign(path, String::from("secret").into_bytes(), &map);
        assert_eq!(res.hash, "teHrl2ZpQpbA1fA4mLcL1at2cBr/qLwn72bEdNgYLCap4+V38rwhBYyYJlubku4kWrZu5CSgxcghyJuapcnD3w==".to_string());
    }

    #[test]
    fn can_gen_params() {
        let mut map: HashMap<String, String> = HashMap::new();
        map.insert("a".to_string(), "a_res".to_string());
        map.insert("b".to_string(), "b_res".to_string());
        let res = kraken::map_to_formdata(&map);
        assert_eq!(
            (res == *"b=b_res&a=a_res" || res == *"a=a_res&b=b_res"),
            true
        );
        map.remove("b");
        let res1 = kraken::map_to_formdata(&map);
        assert_eq!(res1, "a=a_res".to_string());
        map.remove("a");
        let res2 = kraken::map_to_formdata(&map);
        assert_eq!(res2, "".to_string());
    }

    #[test]
    #[should_panic]
    fn can_request_balance() {
        get_test_instance().balance().unwrap();
    }
}

// todo
// 1. clean up
// 2. remove my keys from tests
// 3. release
// 4. improve errors
