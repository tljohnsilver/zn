use anyhow::Result;
use futures::TryStreamExt;
use lance::dataset::{Dataset, WriteMode, WriteParams};
use lance::deps::arrow_array::{
    Array, FixedSizeListArray, Float32Array, RecordBatch, RecordBatchIterator, RecordBatchReader,
    StringArray,
};
use lance::deps::arrow_schema::{DataType, Field, Schema};
use std::sync::Arc;

pub struct VectorMemory {
    base_path: String,
    dim: i32,
    model_id: String,
}

impl VectorMemory {
    pub fn new(base_path: &str, dim: i32, model_id: &str) -> Self {
        Self {
            base_path: base_path.to_string(),
            dim,
            model_id: model_id.to_string(),
        }
    }

    pub fn table_namespace(&self, agent_id: &str) -> String {
        let safe_model: String = self
            .model_id
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        format!("{}/{safe_model}_d{}/{}", self.base_path, self.dim, agent_id)
    }

    /// Store a vector embedding for a specific agent
    pub async fn store(&self, agent_id: &str, text: &str, vector: &[f32]) -> Result<()> {
        let uri = self.table_namespace(agent_id);

        // Define Schema: text (Utf8), vector (FixedSizeList<dim>)
        let dim = self.dim;
        let schema = Arc::new(Schema::new(vec![
            Field::new("text", DataType::Utf8, false),
            Field::new(
                "vector",
                DataType::FixedSizeList(Arc::new(Field::new("item", DataType::Float32, true)), dim),
                false,
            ),
        ]));

        // Build Arrow Arrays
        let text_array = Arc::new(StringArray::from(vec![text])) as Arc<dyn Array>;

        // Build FixedSizeListArray manually
        let values = Arc::new(Float32Array::from(vector.to_vec())) as Arc<dyn Array>;
        let vector_array = Arc::new(
            FixedSizeListArray::try_new(
                Arc::new(Field::new("item", DataType::Float32, true)),
                dim,
                values,
                None,
            )
            .map_err(|e| anyhow::anyhow!("Arrow error: {}", e))?,
        ) as Arc<dyn Array>;

        let batch = RecordBatch::try_new(schema.clone(), vec![text_array, vector_array])
            .map_err(|e| anyhow::anyhow!("Arrow error: {}", e))?;

        // Write to Lance (Append mode)
        // Correcting bounds for Dataset::write
        let reader = Box::new(RecordBatchIterator::new(vec![Ok(batch)], schema.clone()))
            as Box<dyn RecordBatchReader + Send + 'static>;

        let params = WriteParams {
            mode: if std::path::Path::new(&uri).exists() {
                WriteMode::Append
            } else {
                WriteMode::Create
            },
            ..Default::default()
        };

        Dataset::write(reader, &uri, Some(params))
            .await
            .map_err(|e| anyhow::anyhow!("Lance error: {}", e))?;

        Ok(())
    }

    /// Find nearest neighbors (Semantic Search)
    pub async fn search(
        &self,
        agent_id: &str,
        vector: &[f32],
        limit: usize,
    ) -> Result<Vec<(String, f32)>> {
        let uri = self.table_namespace(agent_id);
        if !std::path::Path::new(&uri).exists() {
            return Ok(vec![]);
        }

        let dataset = Dataset::open(&uri)
            .await
            .map_err(|e| anyhow::anyhow!("Lance error: {}", e))?;
        // Scan with vector search
        let mut scanner = dataset.scan();

        // Perform ANN search
        let query_vector = Float32Array::from(vector.to_vec());
        scanner
            .nearest("vector", &query_vector, limit)
            .map_err(|e| anyhow::anyhow!("Lance search error: {}", e))?;

        scanner
            .project(&["text"])
            .map_err(|e| anyhow::anyhow!("Lance project error: {}", e))?;

        let mut results = vec![];
        let mut stream = scanner
            .try_into_stream()
            .await
            .map_err(|e| anyhow::anyhow!("Lance stream error: {}", e))?;

        while let Some(batch) = stream
            .try_next()
            .await
            .map_err(|e| anyhow::anyhow!("Lance next error: {}", e))?
        {
            let text_col = batch
                .column_by_name("text")
                .ok_or_else(|| anyhow::anyhow!("Column 'text' not found"))?
                .as_any()
                .downcast_ref::<StringArray>()
                .ok_or_else(|| anyhow::anyhow!("Column 'text' is not a StringArray"))?;

            let dist_col = batch
                .column_by_name("_distance")
                .ok_or_else(|| anyhow::anyhow!("Column '_distance' not found"))?
                .as_any()
                .downcast_ref::<Float32Array>()
                .ok_or_else(|| anyhow::anyhow!("Column '_distance' is not a Float32Array"))?;

            for i in 0..batch.num_rows() {
                results.push((text_col.value(i).to_string(), dist_col.value(i)));
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_includes_model_id_and_dim() {
        let a = VectorMemory::new("/tmp/v", 384, "minilm-v2");
        let b = VectorMemory::new("/tmp/v", 768, "minilm-v2");
        let c = VectorMemory::new("/tmp/v", 384, "other-model");
        assert_ne!(a.table_namespace("agent"), b.table_namespace("agent"));
        assert_ne!(a.table_namespace("agent"), c.table_namespace("agent"));
        assert!(a.table_namespace("agent").contains("minilm_v2_d384"));
    }
}
