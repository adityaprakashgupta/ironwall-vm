use bayora_llm_engine::LlmEngine;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let model_path = std::env::args().nth(1)
        .unwrap_or_else(|| "../microvm/artifacts/model.gguf".to_string());

    println!("Loading model from: {}", model_path);
    let mut engine = LlmEngine::new()?;
    engine.load(&model_path, 512, 1)?;
    println!("Model loaded successfully");

    let prompts = vec![
        "What is the capital of France?",
        "The sky is",
        "Once upon a time there was",
    ];

    for prompt in &prompts {
        println!("\nPrompt: '{}'", prompt);
        let output = engine.infer(prompt, 16)?;
        println!("Output: '{}'", output);
        println!("Output length: {} bytes", output.len());
        assert!(!output.is_empty(), "LLM produced empty output!");
    }

    println!("\n✓ LLM engine IS producing real text output!");
    Ok(())
}
