use crate::lib::{components::sphincs::{public::SphincsPublic, signature::SphincsSignature}, helpers::random_generator::HashData};

pub enum IdentifingDocument {
    Passport {nationality: String, number: HashData},
    NationalId {nationality: String, number: HashData},
    DriversLicense {nationality: String, number: HashData, car_type: String},
}

pub struct HomeAddress {
    pub address1: String,
    pub address2: Option<String>,
    pub city: String,
    pub state: String,
    pub postcode: String,
    pub country: String,
}



// Sha validation methods don't provide the data itself, but a SHA256 of the data + public seed. The data itself may be provided by the certificate
pub enum ValidationMethod {
    ParentKey(HashData),
    Domain(HashData),
    Phone(HashData),
    Email(HashData),
    IdDocument(IdentifingDocument),
    LivingAddress(HashData),
    HomeAddress(HashData),
}

pub struct SphincsCertificateRequest<const K: usize, const A: usize, const LAYERS: usize, const  TREE_HEIGHT: usize> {
    pub key: SphincsPublic<K, A, LAYERS, TREE_HEIGHT>,
    pub name: String,
    pub phone: Option<String>,
    pub address: Option<HomeAddress>,
    pub domain: Option<String>,
    pub data: Option<String>, // expecting JSON formatted
    pub requested_time: u32,
    pub validation_by: Vec<ValidationMethod>
}

pub struct SphincsCertificate<const K: usize, const A: usize, const LAYERS: usize, const TREE_HEIGHT: usize> {
    pub request: SphincsCertificateRequest<K, A, LAYERS, TREE_HEIGHT>,
    pub signature: SphincsSignature<K, A, LAYERS, TREE_HEIGHT>
}