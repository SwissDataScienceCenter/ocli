use pyo3::prelude::*;
use pyo3::{exceptions::PyValueError, types::PyType};

#[pyclass]
#[derive(Clone)]
pub struct DeviceCodeDataWrapper {
    device_code_data: ocli::DeviceCodeData,
}

#[pymethods]
impl DeviceCodeDataWrapper {
    pub fn __str__(&self) -> String {
        format!("DeviceCodeData(url={})", self.device_code_data.verify_url)
    }
    pub fn __repr__(&self) -> String {
        format!("DeviceCodeData(url={})", self.device_code_data.verify_url)
    }
    pub fn verify_url(&self) -> String {
        self.device_code_data.verify_url.clone()
    }
    pub fn verify_url_full(&self) -> String {
        self.device_code_data.verify_url_full.clone()
    }
    pub fn user_code(&self) -> String {
        self.device_code_data.user_code.clone()
    }
}

#[pyfunction]
pub fn start_device_code_flow(
    url: String,
    client_id: String,
    scopes: Vec<String>,
) -> PyResult<DeviceCodeDataWrapper> {
    let data = ocli::start_device_code_flow(url, client_id, scopes)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(DeviceCodeDataWrapper {
        device_code_data: data,
    })
}

#[pyclass]
#[derive(Debug, Clone)]
pub struct OIDCTokenSet {
    #[pyo3(get)]
    pub access_token: String,
    #[pyo3(get)]
    pub refresh_token: Option<String>,
}

#[pymethods]
impl OIDCTokenSet {
    pub fn __str__(&self) -> String {
        "OIDCTokenSet(redacted)".to_string()
    }
    pub fn __repr__(&self) -> String {
        "OIDCTokenSet(redacted)".to_string()
    }
}

#[pyfunction]
pub fn finish_device_code_flow(data: DeviceCodeDataWrapper) -> PyResult<OIDCTokenSet> {
    let token = ocli::finish_device_code_flow(data.device_code_data)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(OIDCTokenSet {
        access_token: token.access_token().to_string(),
        refresh_token: token.refresh_token().map(|r| r.to_string()),
    })
}

#[pyclass]
#[derive(Clone)]
pub struct Config {
    config: ocli::Config,
}

#[pyclass]
#[derive(Clone)]
pub struct ApplyResult {
    #[pyo3(get)]
    successful: Vec<String>,
    #[pyo3(get)]
    failed: Vec<String>,
}
#[pymethods]
impl Config {
    pub fn __str__(&self) -> String {
        format!("Config({})", self.config.name)
    }
    pub fn __repr__(&self) -> String {
        format!("Config({})", self.config.name)
    }

    #[classmethod]
    pub fn load(_cls: &Bound<'_, PyType>, url: String) -> PyResult<Config> {
        let config =
            ocli::Config::download(url).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Config { config })
    }

    pub fn start_device_code_flow(&self) -> PyResult<DeviceCodeDataWrapper> {
        start_device_code_flow(
            self.config.url.clone(),
            self.config.client_id.clone(),
            self.config.scopes.clone(),
        )
    }
    pub fn finish_device_code_flow(&self, data: DeviceCodeDataWrapper) -> PyResult<OIDCTokenSet> {
        finish_device_code_flow(data)
    }

    pub fn apply(&self, tokenset: OIDCTokenSet) -> PyResult<ApplyResult> {
        let result = self
            .config
            .apply(ocli::OIDCTokenset::new(
                tokenset.access_token,
                tokenset.refresh_token,
            ))
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(ApplyResult {
            successful: result.0.iter().map(|s| s.to_string()).collect(),
            failed: result.1.iter().map(|s| s.to_string()).collect(),
        })
    }
}

#[pymethods]
impl ApplyResult {
    pub fn __str__(&self) -> String {
        format!(
            "ApplyResult(success=[{}], failed=[{}]",
            self.successful.join(","),
            self.failed.join(",")
        )
    }
    pub fn __repr__(&self) -> String {
        format!(
            "ApplyResult(success=[{}], failed=[{}]",
            self.successful.join(","),
            self.failed.join(",")
        )
    }
}

#[pymodule]
fn pyocli(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(start_device_code_flow, m)?)?;
    m.add_function(wrap_pyfunction!(finish_device_code_flow, m)?)?;
    m.add_class::<DeviceCodeDataWrapper>()?;
    m.add_class::<OIDCTokenSet>()?;
    m.add_class::<Config>()?;

    Ok(())
}
