use crate::ast::*;
use crate::crypto;
use super::agent_rpc::CallRequest;
use super::agent_rpc::agent_service_client::AgentServiceClient;
use super::registry_rpc::registry_service_client::RegistryServiceClient;
use super::registry_rpc::{LookupRequest, PutSharedRequest};
use super::audit::{AgentError, Event, format_value_safe};
use super::call::{build_completed_call_envelope, build_failed_call_envelope, build_pending_call_envelope, store_call_result};
use super::context::{Context, ContractInfo};
use super::goal::{apply_annotations, build_goal_result, classify_goal_failure, store_goal_result};
use super::memory::{
    ensure_value_safe_for_irreversible_action, inherit_metadata, propagate_container_metadata,
    resolve_path, sanitize_recalled_value,
};
use anyhow::{Result, anyhow};
use async_recursion::async_recursion;
use ed25519_dalek::Signer;
use ring::digest;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{Duration, sleep};
use wasmtime::{Engine, Linker, Module, Store, Val, ValType};

#[async_recursion]
pub async fn eval_expression(expr: &Expression, ctx: &Context) -> Result<AnnotatedValue> {
    match expr {
        Expression::Literal(val) => Ok(propagate_container_metadata(val.clone())),
        Expression::VariableRef(path) => {
            let root_value = if let Ok(v) = ctx.get_variable(&path.root, MemoryScope::Working).await
            {
                v
            } else {
                ctx.get_variable(&path.root, MemoryScope::Session).await?
            };

            resolve_path(&root_value, path)
        }
        Expression::Annotated { expr, annotation } => {
            let mut val = eval_expression(expr, ctx).await?;
            match annotation {
                Annotation::Confidence => val.confidence = Some(1.0),
                Annotation::Sensitive => val.is_sensitive = true,
                Annotation::Uncertain => val.is_uncertain = true,
                Annotation::Approximate => val.is_approximate = true,
            }
            Ok(propagate_container_metadata(val))
        }
        Expression::BinaryOp { left, op, right } => {
            let l_val = eval_expression(left, ctx).await?;
            let r_val = eval_expression(right, ctx).await?;

            let is_approx = l_val.is_approximate || r_val.is_approximate;
            let tolerance = 0.05;

            match op {
                BinaryOperator::Add => {
                    if let (Value::Number(l), Value::Number(r)) = (&l_val.value, &r_val.value) {
                        let mut res = AnnotatedValue::from(Value::Number(l + r));
                        inherit_metadata(&mut res, &l_val);
                        inherit_metadata(&mut res, &r_val);
                        res.is_approximate = is_approx;
                        Ok(res)
                    } else {
                        Err(anyhow!("Invalid types for ADD"))
                    }
                }
                BinaryOperator::Sub => {
                    if let (Value::Number(l), Value::Number(r)) = (&l_val.value, &r_val.value) {
                        let mut res = AnnotatedValue::from(Value::Number(l - r));
                        inherit_metadata(&mut res, &l_val);
                        inherit_metadata(&mut res, &r_val);
                        res.is_approximate = is_approx;
                        Ok(res)
                    } else {
                        Err(anyhow!("Invalid types for SUB"))
                    }
                }
                BinaryOperator::Eq => {
                    let mut res = if let (Value::Number(l), Value::Number(r)) =
                        (&l_val.value, &r_val.value)
                    {
                        if is_approx {
                            let diff = (l - r).abs();
                            let threshold = l.abs().max(r.abs()) * tolerance;
                            AnnotatedValue::from(Value::Boolean(diff <= threshold))
                        } else {
                            AnnotatedValue::from(Value::Boolean(l == r))
                        }
                    } else {
                        AnnotatedValue::from(Value::Boolean(l_val.value == r_val.value))
                    };
                    inherit_metadata(&mut res, &l_val);
                    inherit_metadata(&mut res, &r_val);
                    Ok(res)
                }
                BinaryOperator::Gt => {
                    if let (Value::Number(l), Value::Number(r)) = (&l_val.value, &r_val.value) {
                        let mut res = if is_approx {
                            AnnotatedValue::from(Value::Boolean(l > &(r * (1.0 - tolerance))))
                        } else {
                            AnnotatedValue::from(Value::Boolean(l > r))
                        };
                        inherit_metadata(&mut res, &l_val);
                        inherit_metadata(&mut res, &r_val);
                        Ok(res)
                    } else {
                        Err(anyhow!("GT only supports numbers"))
                    }
                }
                BinaryOperator::Lt => {
                    if let (Value::Number(l), Value::Number(r)) = (&l_val.value, &r_val.value) {
                        let mut res = if is_approx {
                            AnnotatedValue::from(Value::Boolean(l < &(r * (1.0 + tolerance))))
                        } else {
                            AnnotatedValue::from(Value::Boolean(l < r))
                        };
                        inherit_metadata(&mut res, &l_val);
                        inherit_metadata(&mut res, &r_val);
                        Ok(res)
                    } else {
                        Err(anyhow!("LT only supports numbers"))
                    }
                }
            }
        }
    }
}

#[async_recursion]
pub async fn eval(statement: &Statement, ctx: Context) -> Result<()> {
    match statement {
        Statement::Goal {
            name,
            body,
            outputs,
            result_into,
            retry,
            on_fail,
            deadline,
            wait,
            idempotent,
            audit_trail,
            confirm_with: _confirm_with, // TODO: implement human-in-the-loop confirmation
            timeout_confirmation: _timeout_confirmation, // TODO: implement confirmation timeout
            fallback,
        } => {
            println!("  [Runtime] Goal: {}", name);
            ctx.goals.lock().unwrap_or_else(|e| e.into_inner()).insert(
                name.clone(),
                GoalDefinition {
                    body: body.clone(),
                    outputs: outputs.clone(),
                    result_into: result_into.clone(),
                    retry: retry.map(|n| n as usize),
                    on_fail: on_fail.clone(),
                    deadline: *deadline,
                    wait: *wait,
                    idempotent: *idempotent,
                    audit_trail: *audit_trail,
                    // Preserve parsed values even though execution of these fields
                    // is not yet implemented; keeps GoalDefinition consistent with AST.
                    confirm_with: _confirm_with.clone(),
                    timeout_confirmation: *_timeout_confirmation,
                    fallback: None,
                },
            );

            if *idempotent {
                let audit = ctx.audit_chain.lock().unwrap_or_else(|e| e.into_inner());
                if audit
                    .entries
                    .iter()
                    .any(|e| e.op.starts_with(&format!("GOAL_SUCCESS:{}", name)))
                {
                    println!(
                        "  [Runtime] Goal '{}' marked IDEMPOTENT and already succeeded. Skipping.",
                        name
                    );
                    return Ok(());
                }
            }

            if let Some(delay) = wait {
                sleep(Duration::from_secs_f64(*delay)).await;
            }

            let max_retries = retry.unwrap_or(0);
            use tokio::task::JoinSet;

            let mut goal_tasks = JoinSet::new();
            let body_clone = body.clone();
            let ctx_clone = ctx.clone();
            let name_clone = name.clone();
            let outputs_clone = outputs.clone();
            let result_into_clone = result_into.clone();
            let working_before = ctx.working_variables.lock().unwrap().clone();
            let audit_enabled = *audit_trail;

            goal_tasks.spawn(async move {
                let mut current_attempt = 0;
                loop {
                    current_attempt += 1;
                    let mut res = Ok(());
                    for stmt in &body_clone {
                        if let Err(e) = eval(stmt, ctx_clone.clone()).await {
                            res = Err(e);
                            break;
                        }
                    }

                    match res {
                        Ok(_) => {
                            let goal_result = build_goal_result(
                                &ctx_clone,
                                &name_clone,
                                &working_before,
                                &outputs_clone,
                                &result_into_clone,
                            )
                            .await?;

                            store_goal_result(&ctx_clone, &name_clone, goal_result).await?;
                            if audit_enabled {
                                let mut audit = ctx_clone
                                    .audit_chain
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner());
                                audit.append(format!("GOAL_SUCCESS:{}", name_clone));
                            }
                            return Ok::<(), anyhow::Error>(());
                        }
                        Err(e) => {
                            if current_attempt <= max_retries {
                                println!(
                                    "  [Runtime] Goal '{}' attempt {} failed: {}. Retrying...",
                                    name_clone, current_attempt, e
                                );
                            } else {
                                println!(
                                    "  [Runtime] Goal '{}' exhausted all {} retries.",
                                    name_clone,
                                    max_retries + 1
                                );
                                return Err(e);
                            }
                        }
                    }
                }
            });

            let result = if let Some(d) = deadline {
                match tokio::time::timeout(Duration::from_secs_f64(*d), goal_tasks.join_next())
                    .await
                {
                    Ok(Some(joined)) => joined.map_err(|e| anyhow!("Goal task failed: {}", e))?,
                    Ok(None) => Err(anyhow!("Goal task completed without a result")),
                    Err(_) => {
                        goal_tasks.abort_all();
                        while goal_tasks.join_next().await.is_some() {}
                        Err(anyhow!("Goal '{}' timed out after {}s", name, d))
                    }
                }
            } else {
                match goal_tasks.join_next().await {
                    Some(joined) => joined.map_err(|e| anyhow!("Goal task failed: {}", e))?,
                    None => Err(anyhow!("Goal task completed without a result")),
                }
            };

            if let Err(e) = result {
                let failure_type = classify_goal_failure(&e);

                if let Some(fail_stmt) = on_fail
                    .get(&failure_type)
                    .or_else(|| on_fail.get(&GoalFailureType::Any))
                {
                    eval(fail_stmt, ctx.clone()).await
                } else if let Some(fallback_stmt) = fallback {
                    eval(fallback_stmt, ctx.clone()).await
                } else {
                    Err(e)
                }
            } else {
                Ok(())
            }
        }
        Statement::Set { variable, value } => {
            let val = eval_expression(value, &ctx).await?;
            ctx.set_variable(variable.clone(), val, MemoryScope::Working)
                .await?;
            Ok(())
        }
        Statement::If {
            condition,
            then_branch,
            else_branch,
        } => {
            let cond = eval_expression(condition, &ctx).await?;
            let is_true = match cond.value {
                Value::Boolean(b) => b,
                Value::Number(n) => n != 0.0,
                Value::Text(s) => !s.is_empty(),
                Value::List(l) => !l.is_empty(),
                Value::Object(o) => !o.is_empty(),
                Value::Null => false,
            };
            if is_true {
                for stmt in then_branch {
                    eval(stmt, ctx.clone()).await?;
                }
            } else if let Some(branch) = else_branch {
                for stmt in branch {
                    eval(stmt, ctx.clone()).await?;
                }
            }
            Ok(())
        }
        Statement::UseTool {
            tool_name,
            args,
            result_into,
        } => {
            ctx.check_contracts(tool_name)?;
            println!("  [Runtime] USE TOOL: {}", tool_name);

            // 1. Lookup Tool Definition
            let tool = {
                let tools = ctx.tools.lock().unwrap();
                tools.get(tool_name).cloned().ok_or_else(|| {
                    anyhow!(AgentError {
                        failure_type: GoalFailureType::ToolFail,
                        message: format!("Tool '{}' not found in registry", tool_name),
                    })
                })?
            };

            // 2. Rate Limiting
            if let Some(ref limit_str) = tool.rate_limit {
                // Simple implementation: "N/period" (e.g., "10/1m")
                let parts: Vec<&str> = limit_str.split('/').collect();
                if parts.len() == 2
                    && let Ok(max_calls) = parts[0].parse::<usize>()
                {
                    let period_secs = match parts[1] {
                        "1s" => 1,
                        "1m" => 60,
                        "1h" => 3600,
                        _ => 60, // Default to 1 minute
                    };

                    let mut timestamps = ctx
                        .tool_call_timestamps
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    let calls = timestamps.entry(tool_name.clone()).or_default();
                    let now = std::time::Instant::now();

                    // Clean up old timestamps
                    calls.retain(|t| now.duration_since(*t).as_secs() < period_secs);

                    if calls.len() >= max_calls {
                        return Err(anyhow!(AgentError {
                            failure_type: GoalFailureType::ToolFail,
                            message: format!(
                                "Rate limit exceeded for tool '{}': {}",
                                tool_name, limit_str
                            ),
                        }));
                    }
                    calls.push(now);
                }
            }

            // 3. Evaluate and Validate Inputs
            let mut evaluated_args = HashMap::new();
            for (name, expr) in args {
                evaluated_args.insert(name.clone(), eval_expression(expr, &ctx).await?);
            }

            for input_field in &tool.inputs {
                if input_field.required && !evaluated_args.contains_key(&input_field.name) {
                    return Err(anyhow!(AgentError {
                        failure_type: GoalFailureType::ToolFail,
                        message: format!(
                            "Missing required input '{}' for tool '{}'",
                            input_field.name, tool_name
                        ),
                    }));
                }
                // Basic type hint validation (prototype)
                if let Some(arg_val) = evaluated_args.get(&input_field.name) {
                    match input_field.type_hint.as_str() {
                        "number" | "float" | "int" => {
                            if !matches!(arg_val.value, Value::Number(_)) {
                                return Err(anyhow!(AgentError {
                                    failure_type: GoalFailureType::ToolFail,
                                    message: format!(
                                        "Type mismatch for '{}': expected number, found {:?}",
                                        input_field.name, arg_val.value
                                    ),
                                }));
                            }
                        }
                        "text" | "string" => {
                            if !matches!(arg_val.value, Value::Text(_)) {
                                return Err(anyhow!(AgentError {
                                    failure_type: GoalFailureType::ToolFail,
                                    message: format!(
                                        "Type mismatch for '{}': expected text, found {:?}",
                                        input_field.name, arg_val.value
                                    ),
                                }));
                            }
                        }
                        _ => {} // Skip others for now
                    }
                }
            }

            // 4. Execute (Native or Mock)
            let execution_future = async {
                let handler = {
                    let handlers = ctx.tool_handlers.lock().unwrap_or_else(|e| e.into_inner());
                    handlers.get(tool_name).cloned()
                };

                if let Some(h) = handler {
                    // Use spawn_blocking to ensure we don't freeze the executor
                    // and allow timeouts to interrupt.
                    let args_for_spawn = evaluated_args.clone();
                    tokio::task::spawn_blocking(move || h(args_for_spawn))
                        .await
                        .map_err(|e| anyhow!("Tool execution panicked: {}", e))?
                } else {
                    // Fallback: Mock result based on schema
                    let mut res_fields = HashMap::new();
                    for output_field in &tool.outputs {
                        let mock_val = match output_field.type_hint.as_str() {
                            "number" | "float" | "int" => Value::Number(1.0),
                            "boolean" => Value::Boolean(true),
                            _ => Value::Text(format!("Mock result for {}", output_field.name)),
                        };
                        res_fields
                            .insert(output_field.name.clone(), AnnotatedValue::from(mock_val));
                    }
                    Ok(AnnotatedValue::from(Value::Object(res_fields)))
                }
            };

            let result = if let Some(d) = tool.timeout {
                match tokio::time::timeout(Duration::from_secs_f64(d), execution_future).await {
                    Ok(res) => res,
                    Err(_) => Err(anyhow!(AgentError {
                        failure_type: GoalFailureType::Timeout,
                        message: format!("Tool '{}' timed out after {}s", tool_name, d),
                    })),
                }
            } else {
                execution_future.await
            };

            let final_val = match result {
                Ok(val) => {
                    // 5. Audit Trail for Side Effects
                    if tool.side_effect {
                        let mut audit = ctx.audit_chain.lock().unwrap_or_else(|e| e.into_inner());
                        audit.append(format!("TOOL_EXEC:{}:{:?}", tool_name, evaluated_args));
                    }
                    val
                }
                Err(e) => return Err(e),
            };

            // 6. Assign result
            if let Some(path) = result_into {
                ctx.set_variable_path(path, final_val, MemoryScope::Working)
                    .await?;
            }
            Ok(())
        }
        Statement::Parallel {
            pattern,
            branches,
            result_into,
            deadline,
        } => {
            let mut join_set = tokio::task::JoinSet::new();
            for (i, branch) in branches.iter().enumerate() {
                let branch_clone = branch.clone();
                let ctx_clone = ctx.clone();
                let branch_index = i;
                join_set.spawn(async move {
                    // Track variable changes in this branch
                    let vars_before = ctx_clone
                        .working_variables
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone();
                    for stmt in &branch_clone {
                        eval(stmt, ctx_clone.clone()).await?;
                    }
                    let vars_after = ctx_clone
                        .working_variables
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone();
                    let mut changes = HashMap::new();
                    for (k, v) in vars_after {
                        if vars_before.get(&k) != Some(&v) {
                            changes.insert(k, v);
                        }
                    }
                    Ok::<(usize, HashMap<String, AnnotatedValue>), anyhow::Error>((
                        branch_index,
                        changes,
                    ))
                });
            }

            let pattern_clone = pattern.clone();
            let parallel_future = async move {
                let mut results = HashMap::new();
                match pattern_clone {
                    ParallelPattern::Gather | ParallelPattern::GatherAll => {
                        let mut branch_errors = Vec::new();
                        while let Some(res) = join_set.join_next().await {
                            match res? {
                                Ok((idx, changes)) => {
                                    results.insert(
                                        format!("branch_{}", idx),
                                        AnnotatedValue::from(Value::Object(changes)),
                                    );
                                }
                                Err(e) => branch_errors.push(e),
                            }
                        }
                        if pattern_clone == ParallelPattern::Gather && !branch_errors.is_empty() {
                            return Err(branch_errors.remove(0));
                        }
                        Ok::<AnnotatedValue, anyhow::Error>(AnnotatedValue::from(Value::Object(
                            results,
                        )))
                    }
                    ParallelPattern::Race => {
                        while let Some(res) = join_set.join_next().await {
                            if let Ok(Ok((idx, changes))) = res {
                                join_set.abort_all();
                                results.insert(
                                    "winner".to_string(),
                                    AnnotatedValue::from(Value::Number(idx as f64)),
                                );
                                results.insert(
                                    "data".to_string(),
                                    AnnotatedValue::from(Value::Object(changes)),
                                );
                                return Ok(AnnotatedValue::from(Value::Object(results)));
                            }
                        }
                        Err(anyhow!("All branches in RACE failed"))
                    }
                    ParallelPattern::GatherMin(n) => {
                        let mut success_count = 0;
                        while let Some(res) = join_set.join_next().await {
                            if let Ok(Ok((idx, changes))) = res {
                                results.insert(
                                    format!("branch_{}", idx),
                                    AnnotatedValue::from(Value::Object(changes)),
                                );
                                success_count += 1;
                                if success_count >= n {
                                    // We have enough results; cancel remaining tasks.
                                    join_set.abort_all();
                                    break;
                                }
                            }
                        }
                        if success_count < n {
                            return Err(anyhow!(
                                "GATHER_MIN failed: only {} branches succeeded",
                                success_count
                            ));
                        }
                        Ok(AnnotatedValue::from(Value::Object(results)))
                    }
                }
            };

            let result = if let Some(d) = deadline {
                match tokio::time::timeout(Duration::from_secs_f64(*d), parallel_future).await {
                    Ok(res) => res,
                    Err(_) => Err(anyhow!("Parallel block timed out after {}s", d)),
                }
            } else {
                parallel_future.await
            };

            match result {
                Ok(agg_val) => {
                    if let Some(path) = result_into {
                        ctx.set_variable_path(path, agg_val, MemoryScope::Working)
                            .await?;
                    }
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        Statement::Delegate {
            agent_id,
            goal_name,
            args,
        } => {
            ctx.check_contracts(goal_name)?;
            println!(
                "  [Runtime] DELEGATING goal '{}' to agent '{}'",
                goal_name, agent_id
            );

            let mut rpc_args = HashMap::new();
            for (k, expr) in args {
                let val = eval_expression(expr, &ctx).await?;
                ensure_value_safe_for_irreversible_action(
                    &val,
                    &format!("delegate argument '{}' to agent '{}'", k, agent_id),
                )?;
                rpc_args.insert(k.clone(), format!("{:?}", val.value));
            }

            let caller_id = ctx
                .agent_id
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            let ctx_clone = ctx.clone();
            let agent_id_clone = agent_id.clone();
            let goal_name_clone = goal_name.clone();

            tokio::spawn(async move {
                let _ = async {
                    let mut lookup_res = None;
                    let registries = ctx_clone
                        .registries
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone();

                    for reg_addr in registries {
                        if let Ok(mut reg_client) =
                            RegistryServiceClient::connect(reg_addr.clone()).await
                            && let Ok(res) = reg_client
                                .lookup_agent(LookupRequest {
                                    agent_id: agent_id_clone.clone(),
                                    ttl: 3,
                                })
                                .await
                        {
                            let res = res.into_inner();
                            if res.found {
                                lookup_res = Some(res);
                                break;
                            }
                        }
                    }

                    if let Some(lookup_data) = lookup_res {
                        let payload = format!("{}:{}", goal_name_clone, caller_id);
                        let signature = ctx_clone
                            .identity
                            .signing_key
                            .sign(payload.as_bytes())
                            .to_bytes()
                            .to_vec();

                        if let Ok(mut agent_client) =
                            AgentServiceClient::connect(lookup_data.endpoint.clone()).await
                        {
                            let _ = agent_client
                                .call_goal(CallRequest {
                                    goal_name: goal_name_clone,
                                    args: rpc_args,
                                    caller_id,
                                    signature,
                                })
                                .await;
                        }
                    }
                }
                .await;
            });

            Ok(())
        }
        Statement::ForEach { item, list, body } => {
            let list_val = eval_expression(list, &ctx).await?;
            if let Value::List(elements) = list_val.value {
                for element in elements {
                    ctx.set_variable(item.clone(), element, MemoryScope::Working)
                        .await?;
                    for stmt in body {
                        eval(stmt, ctx.clone()).await?;
                    }
                }
                Ok(())
            } else {
                Err(anyhow!(
                    "FOREACH expects a list, found {:?}",
                    list_val.value
                ))
            }
        }
        Statement::Repeat { condition, body } => {
            loop {
                let cond = eval_expression(condition, &ctx).await?;
                let is_true = match cond.value {
                    Value::Boolean(b) => b,
                    Value::Number(n) => n != 0.0,
                    Value::Text(s) => !s.is_empty(),
                    Value::List(l) => !l.is_empty(),
                    Value::Object(o) => !o.is_empty(),
                    Value::Null => false,
                };
                if is_true {
                    break;
                }

                for stmt in body {
                    eval(stmt, ctx.clone()).await?;
                }
            }
            Ok(())
        }
        Statement::Wait { duration } => {
            sleep(Duration::from_secs_f64(*duration)).await;
            Ok(())
        }
        Statement::Remember {
            name,
            value,
            scope,
            expires,
        } => {
            let val = eval_expression(value, &ctx).await?;
            if *scope == MemoryScope::Shared {
                ensure_value_safe_for_irreversible_action(
                    &val,
                    &format!("write shared memory '{}'", name),
                )?;
            }
            ctx.set_variable(name.clone(), val, *scope).await?;

            // Schedule automatic removal after the requested duration.
            if let Some(expires_secs) = expires {
                let ctx_clone = ctx.clone();
                let name_clone = name.clone();
                let scope_clone = *scope;
                let delay = *expires_secs;
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs_f64(delay)).await;
                    match scope_clone {
                        MemoryScope::Working => {
                            ctx_clone
                                .working_variables
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .remove(&name_clone);
                        }
                        MemoryScope::Session => {
                            ctx_clone
                                .session_variables
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .remove(&name_clone);
                        }
                        MemoryScope::LongTerm => {
                            if let Ok(mut memory) =
                                ctx_clone.long_term_backend.load(&ctx_clone.session_key)
                            {
                                memory.remove(&name_clone);
                                let _ = ctx_clone
                                    .long_term_backend
                                    .save(&ctx_clone.session_key, memory);
                            }
                        }
                        MemoryScope::Shared => {} // Shared expiry is not supported via current registry protocol
                    }
                });
            }
            Ok(())
        }
        Statement::Recall {
            name,
            into_var,
            scope,
            on_missing,
            fuzzy,
            threshold,
        } => {
            let result = if *fuzzy {
                // Fuzzy search over Shared scope is not supported because the registry
                // protocol only provides point lookups, not full key enumeration.
                if *scope == MemoryScope::Shared {
                    return Err(anyhow!(
                        "Fuzzy RECALL is not supported for Shared scope; use exact RECALL instead"
                    ));
                }
                let memory: HashMap<String, AnnotatedValue> = match scope {
                    MemoryScope::Working => ctx
                        .working_variables
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone(),
                    MemoryScope::Session => ctx
                        .session_variables
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone(),
                    MemoryScope::LongTerm => ctx.long_term_backend.load(&ctx.session_key)?,
                    MemoryScope::Shared => unreachable!(),
                };
                ctx.long_term_backend
                    .fuzzy_search(name, &memory, *threshold)?
                    .ok_or_else(|| anyhow!("Fuzzy match not found"))
            } else {
                ctx.get_variable(name, *scope).await
            };

            match result {
                Ok(val) => {
                    let recalled = sanitize_recalled_value(val, *scope);
                    ctx.set_variable(into_var.clone(), recalled, MemoryScope::Working)
                        .await?;
                }
                Err(_) => {
                    if let Some(expr) = on_missing {
                        let val = eval_expression(expr, &ctx).await?;
                        ctx.set_variable(into_var.clone(), val, MemoryScope::Working)
                            .await?;
                    } else {
                        return Err(anyhow!("Key '{}' not found", name));
                    }
                }
            }
            Ok(())
        }
        Statement::Forget { name, scope } => {
            match scope {
                MemoryScope::Working => {
                    ctx.working_variables
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(name);
                }
                MemoryScope::Session => {
                    ctx.session_variables
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(name);
                }
                MemoryScope::LongTerm => {
                    let mut memory = ctx.long_term_backend.load(&ctx.session_key)?;
                    memory.remove(name);
                    ctx.long_term_backend.save(&ctx.session_key, memory)?;
                }
                MemoryScope::Shared => {
                    return Err(anyhow!(
                        "FORGET for Shared scope is not supported: \
                         the registry protocol does not provide a delete operation"
                    ));
                }
            }
            Ok(())
        }
        Statement::Agent { .. } => Ok(()),
        Statement::Contract {
            name,
            issued_by,
            capabilities,
            budget,
            requires_confirmation,
            expires,
        } => {
            // Convert the duration-based `expires` field to an absolute Unix timestamp
            // so that check_contracts can correctly compare against the current time.
            let expires_at = expires.map(|duration_secs| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    .saturating_add(duration_secs as u64)
            });
            ctx.active_contracts
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(
                    name.clone(),
                    ContractInfo {
                        issued_by: issued_by.clone(),
                        capabilities: capabilities.clone(),
                        budget: *budget,
                        requires_confirmation: *requires_confirmation,
                        expires_at,
                    },
                );
            Ok(())
        }
        Statement::Emit { event, data } => {
            if let Some(expr) = data {
                let val = eval_expression(expr, &ctx).await?;
                ensure_value_safe_for_irreversible_action(
                    &val,
                    &format!("emit event '{}'", event),
                )?;
                let _ = ctx.event_tx.send(Event {
                    name: event.clone(),
                    data: val,
                });
            } else {
                let _ = ctx.event_tx.send(Event {
                    name: event.clone(),
                    data: AnnotatedValue::from(Value::Null),
                });
            }
            Ok(())
        }
        Statement::On { event, handler } => {
            let event_name = event.clone();
            let handler_clone = handler.clone();
            let ctx_clone = ctx.clone();
            let mut rx = ctx.event_tx.subscribe();
            tokio::spawn(async move {
                while let Ok(ev) = rx.recv().await {
                    if ev.name == event_name {
                        // Inject event payload
                        let mut event_obj = HashMap::new();
                        event_obj.insert("payload".to_string(), ev.data);
                        let _ = ctx_clone
                            .set_variable(
                                "event".to_string(),
                                AnnotatedValue::from(Value::Object(event_obj)),
                                MemoryScope::Working,
                            )
                            .await;

                        for stmt in &handler_clone {
                            let _ = eval(stmt, ctx_clone.clone()).await;
                        }
                    }
                }
            });
            Ok(())
        }
        Statement::Prove {
            statements,
            claim,
            proof_name,
        } => {
            for stmt in statements {
                eval(stmt, ctx.clone()).await?;
            }

            let mut state_repr = String::new();
            {
                let vars = ctx
                    .working_variables
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let mut keys: Vec<_> = vars.keys().collect();
                keys.sort();
                for k in keys {
                    let v = vars.get(k).unwrap();
                    state_repr.push_str(&format!("{}:{:?}|", k, v.value));
                }
            }

            let hash = digest::digest(&digest::SHA256, state_repr.as_bytes());
            let hash_bytes = hash.as_ref();
            let mut steps =
                32 + (u32::from_be_bytes(hash_bytes[0..4].try_into().unwrap()) % 64) as usize;

            // Winterfell requires power-of-two trace length
            if !steps.is_power_of_two() {
                steps = steps.next_power_of_two();
            }

            let proof = crypto::generate_proof(steps, claim)?;
            ctx.proofs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(proof_name.clone(), proof);
            Ok(())
        }
        Statement::Reveal {
            proof_name,
            claim,
            to_agent: _,
            result_into,
        } => {
            let proof = {
                let proofs = ctx.proofs.lock().unwrap_or_else(|e| e.into_inner());
                proofs
                    .get(proof_name)
                    .cloned()
                    .ok_or_else(|| anyhow!("Proof '{}' not found", proof_name))?
            };

            crypto::verify_proof(&proof, claim)?;

            if let Some(path) = result_into {
                let reveal_val = AnnotatedValue::from(Value::Text(format!(
                    "Unlocked via proof {} for claim {}",
                    proof_name, claim
                )));
                ctx.set_variable_path(path, reveal_val, MemoryScope::Working)
                    .await?;
            }
            Ok(())
        }
        Statement::UseWasm {
            module_path,
            function_name,
            args,
            result_into,
        } => {
            ctx.check_contracts(function_name)?;
            let module = Module::from_file(&ctx.wasm_engine, module_path)?;
            let mut store = Store::new(&ctx.wasm_engine, ());
            store.set_fuel(1_000_000)?;
            let linker = Linker::new(&ctx.wasm_engine);
            let instance = linker.instantiate(&mut store, &module)?;

            let func = instance
                .get_func(&mut store, function_name)
                .ok_or_else(|| anyhow!("Function '{}' not found in WASM module", function_name))?;

            let param_types: Vec<ValType> = func.ty(&store).params().collect();
            let mut wasm_args = Vec::new();

            for (i, (_name, expr)) in args.iter().enumerate() {
                if i >= param_types.len() {
                    break;
                }
                let val = eval_expression(expr, &ctx).await?;
                let p_type = &param_types[i];

                let wasm_val = match (p_type, &val.value) {
                    (ValType::I32, Value::Number(n)) => Val::I32(*n as i32),
                    (ValType::I32, Value::Text(s)) => {
                        let memory = instance
                            .get_memory(&mut store, "memory")
                            .ok_or_else(|| anyhow!("Memory export not found for string passing"))?;
                        let alloc_func =
                            instance.get_func(&mut store, "alloc").ok_or_else(|| {
                                anyhow!("'alloc' export required to pass strings to WASM")
                            })?;

                        let mut alloc_res = vec![Val::I32(0)];
                        alloc_func.call(&mut store, &[Val::I32(s.len() as i32)], &mut alloc_res)?;
                        let ptr = alloc_res[0].i32().unwrap();

                        memory.write(&mut store, ptr as usize, s.as_bytes())?;
                        Val::I32(ptr)
                    }
                    (ValType::I64, Value::Number(n)) => Val::I64(*n as i64),
                    (ValType::F32, Value::Number(n)) => Val::F32((*n as f32).to_bits()),
                    (ValType::F64, Value::Number(n)) => Val::F64(n.to_bits()),
                    (ValType::I32, Value::Boolean(b)) => Val::I32(if *b { 1 } else { 0 }),
                    _ => {
                        return Err(anyhow!(
                            "WASM type mismatch for parameter {}: expected {:?}, got {:?}",
                            i,
                            p_type,
                            val.value
                        ));
                    }
                };
                wasm_args.push(wasm_val);
            }

            let result_types: Vec<ValType> = func.ty(&store).results().collect();
            let mut results = vec![Val::I32(0); result_types.len()];

            func.call(&mut store, &wasm_args, &mut results)?;

            let res_val = if let Some(res) = results.first() {
                match res {
                    Val::I32(ptr) => {
                        let has_alloc = instance.get_func(&mut store, "alloc").is_some();
                        if has_alloc {
                            if let Some(memory) = instance.get_memory(&mut store, "memory") {
                                let data = memory.data(&store);
                                let ptr_usize = *ptr as usize;
                                if ptr_usize < data.len() && ptr_usize > 0 {
                                    let end = data[ptr_usize..]
                                        .iter()
                                        .position(|&b| b == 0)
                                        .unwrap_or(data.len() - ptr_usize);
                                    if end > 0 {
                                        if let Ok(s) =
                                            std::str::from_utf8(&data[ptr_usize..ptr_usize + end])
                                        {
                                            Value::Text(s.to_string())
                                        } else {
                                            Value::Number(*ptr as f64)
                                        }
                                    } else {
                                        Value::Number(*ptr as f64)
                                    }
                                } else {
                                    Value::Number(*ptr as f64)
                                }
                            } else {
                                Value::Number(*ptr as f64)
                            }
                        } else {
                            Value::Number(*ptr as f64)
                        }
                    }
                    Val::I64(i) => Value::Number(*i as f64),
                    Val::F32(f) => Value::Number(f32::from_bits(*f) as f64),
                    Val::F64(f) => Value::Number(f64::from_bits(*f)),
                    _ => return Err(anyhow!("Unsupported WASM return type")),
                }
            } else {
                Value::Boolean(true)
            };

            let mock_result = AnnotatedValue::from(res_val);
            if let Some(path) = result_into {
                ctx.set_variable_path(path, mock_result, MemoryScope::Working)
                    .await?;
            }
            Ok(())
        }
        Statement::Call {
            agent_id,
            goal_name,
            args,
            timeout,
            signed_by,
            result_into,
        } => {
            ctx.check_contracts(goal_name)?;
            let mut rpc_args = HashMap::new();
            let mut evaluated_args: HashMap<String, AnnotatedValue> = HashMap::new();
            for (k, expr) in args {
                let val = eval_expression(expr, &ctx).await?;
                ensure_value_safe_for_irreversible_action(
                    &val,
                    &format!("send argument '{}' to agent '{}'", k, agent_id),
                )?;
                rpc_args.insert(k.clone(), serde_json::to_string(&val)?);
                evaluated_args.insert(k.clone(), val);
            }

            let call_id_str = result_into
                .as_ref()
                .map(|p| p.root.clone())
                .unwrap_or_else(|| agent_id.clone());

            let pending_envelope =
                build_pending_call_envelope(&call_id_str, agent_id, goal_name, &evaluated_args);
            store_call_result(&ctx, &call_id_str, pending_envelope).await?;

            let (tx, rx) = tokio::sync::oneshot::channel();
            if let Some(path) = result_into {
                ctx.pending_calls
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(path.root.clone(), rx);
            }

            let caller_id = ctx
                .agent_id
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            let ctx_clone = ctx.clone();
            let agent_id_clone = agent_id.clone();
            let goal_name_clone = goal_name.clone();
            let timeout_val = *timeout;
            let _signed_by_val = signed_by.clone(); // TODO: verify incoming signature against registered key
            let result_into_clone = call_id_str;
            let evaluated_args_clone = evaluated_args.clone();

            tokio::spawn(async move {
                let res = async {
                    let mut lookup_res = None;
                    let registries = ctx_clone
                        .registries
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone();

                    for reg_addr in registries {
                        if let Ok(mut reg_client) =
                            RegistryServiceClient::connect(reg_addr.clone()).await
                            && let Ok(res) = reg_client
                                .lookup_agent(LookupRequest {
                                    agent_id: agent_id_clone.clone(),
                                    ttl: 3,
                                })
                                .await
                        {
                            let res = res.into_inner();
                            if res.found {
                                lookup_res = Some((reg_addr, res));
                                break;
                            }
                        }
                    }

                    let (_reg_addr, lookup_data) = lookup_res.ok_or_else(|| {
                        anyhow!(
                            "Agent '{}' not found in any registered registry",
                            agent_id_clone
                        )
                    })?;

                    let payload = format!("{}:{}", goal_name_clone, caller_id);
                    let signature = ctx_clone
                        .identity
                        .signing_key
                        .sign(payload.as_bytes())
                        .to_bytes()
                        .to_vec();

                    let mut agent_client =
                        AgentServiceClient::connect(lookup_data.endpoint.clone()).await?;

                    let rpc_call = agent_client.call_goal(CallRequest {
                        goal_name: goal_name_clone.clone(),
                        args: rpc_args,
                        caller_id,
                        signature,
                    });

                    let response = if let Some(d) = timeout_val {
                        match tokio::time::timeout(Duration::from_secs_f64(d), rpc_call).await {
                            Ok(res) => res?.into_inner(),
                            Err(_) => {
                                return Err(anyhow!(AgentError {
                                    failure_type: GoalFailureType::Timeout,
                                    message: format!(
                                        "Call to '{}' timed out after {}s",
                                        agent_id_clone, d
                                    ),
                                }));
                            }
                        }
                    } else {
                        rpc_call.await?.into_inner()
                    };

                    if response.success {
                        let result = serde_json::from_str::<AnnotatedValue>(&response.result_json)
                            .or_else(|_| {
                                Ok::<AnnotatedValue, serde_json::Error>(AnnotatedValue::from(
                                    Value::Text(response.result_json.clone()),
                                ))
                            })?;
                        Ok(build_completed_call_envelope(
                            &result_into_clone,
                            &agent_id_clone,
                            &goal_name_clone,
                            &evaluated_args_clone,
                            result,
                        ))
                    } else {
                        Ok(build_failed_call_envelope(
                            &result_into_clone,
                            &agent_id_clone,
                            &goal_name_clone,
                            &evaluated_args_clone,
                            &response.result_json,
                        ))
                    }
                }
                .await;

                let envelope = res.unwrap_or_else(|e| {
                    build_failed_call_envelope(
                        &result_into_clone,
                        &agent_id_clone,
                        &goal_name_clone,
                        &evaluated_args_clone,
                        &e.to_string(),
                    )
                });
                let _ = tx.send(envelope);
            });

            Ok(())
        }
        Statement::Await {
            call_id,
            result_into,
        } => {
            let rx = ctx
                .pending_calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(call_id)
                .ok_or_else(|| anyhow!("No pending call found for ID '{}'", call_id))?;

            let envelope = rx
                .await
                .map_err(|_| anyhow!("Call task for '{}' panicked or was dropped", call_id))?;

            if let Some(path) = result_into {
                ctx.set_variable_path(path, envelope, MemoryScope::Working)
                    .await?;
            } else {
                ctx.set_variable(call_id.clone(), envelope, MemoryScope::Working)
                    .await?;
            }
            Ok(())
        }
        Statement::Tool(def) => {
            println!("  [Runtime] Registering TOOL: {}", def.name);
            ctx.tools
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(def.name.clone(), def.clone());
            Ok(())
        }
    }
}

