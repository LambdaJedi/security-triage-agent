
import json
import sys
from pathlib import Path

# Allow imports from the project root
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.triage_agent.agent import analyse_finding


DATASET_PATH = PROJECT_ROOT / "evaluation" / "dataset.json"
OUTPUT_PATH = PROJECT_ROOT / "evaluation" / "results.json"


def load_dataset():
    """Load evaluation examples from the JSON dataset."""

    with open(DATASET_PATH, "r", encoding="utf-8") as file:
        return json.load(file)


def evaluate_cwe(expected_cwe, actual_cwe):
    """Check whether the predicted CWE matches the expected CWE."""

    if expected_cwe is None:
        return actual_cwe is None or actual_cwe == ""

    return expected_cwe == actual_cwe


def evaluate_evidence(assessment, test_case):
    """Check expected and forbidden evidence terms."""

    evidence_text = " ".join(assessment.evidence).lower()

    expected_terms = test_case["expected_evidence_terms"]
    forbidden_terms = test_case["forbidden_evidence_terms"]

    expected_found = [
        term for term in expected_terms
        if term.lower() in evidence_text
    ]

    forbidden_found = [
        term for term in forbidden_terms
        if term.lower() in evidence_text
    ]

    expected_passed = len(expected_found) == len(expected_terms)
    forbidden_passed = len(forbidden_found) == 0

    return {
        "passed": expected_passed and forbidden_passed,
        "expected_terms_found": expected_found,
        "expected_terms_missing": [
            term for term in expected_terms
            if term not in expected_found
        ],
        "forbidden_terms_found": forbidden_found
    }


def evaluate_verified_impact(assessment, expected):
    """Check whether verified impact matches the expected result."""

    text = assessment.verified_impact.lower()

    negative_indicators = [
        "no successful exploitation",
        "not been demonstrated",
        "not demonstrated",
        "not been verified",
        "no impact has been demonstrated",
        "not established"
    ]

    actual_verified = not any(
        indicator in text for indicator in negative_indicators
    )

    return actual_verified == expected


def run_evaluation():
    """Run every evaluation case and calculate metrics."""

    dataset = load_dataset()

    results = []

    total = len(dataset)

    print("\nSTARTING TRIAGE AGENT EVALUATION")
    print("=" * 60)

    for index, test_case in enumerate(dataset, start=1):

        print(
            f"\n[{index}/{total}] "
            f"Running {test_case['id']}: {test_case['category']}"
        )

        try:
            result = analyse_finding(test_case["finding"])

            assessment = result["assessment"]

            cwe_passed = evaluate_cwe(
                test_case["expected_cwe"],
                assessment.cwe
            )

            evidence_result = evaluate_evidence(
                assessment,
                test_case
            )

            impact_passed = evaluate_verified_impact(
                assessment,
                test_case["expected_verified_impact"]
            )

            test_result = {
                "id": test_case["id"],
                "category": test_case["category"],
                "status": "success",
                "predicted_cwe": assessment.cwe,
                "expected_cwe": test_case["expected_cwe"],
                "cwe_passed": cwe_passed,
                "evidence_passed": evidence_result["passed"],
                "evidence_details": evidence_result,
                "impact_passed": impact_passed,
                "predicted_verified_impact": assessment.verified_impact,
                "expected_verified_impact": test_case[
                    "expected_verified_impact"
                ],
                "severity": assessment.severity,
                "confidence": assessment.confidence,
                "tool_calls": result["tool_calls"]
            }

            print(f"  CWE: {'PASS' if cwe_passed else 'FAIL'}")
            print(
                f"  Evidence: "
                f"{'PASS' if evidence_result['passed'] else 'FAIL'}"
            )
            print(f"  Verified impact: {'PASS' if impact_passed else 'FAIL'}")

        except Exception as error:

            test_result = {
                "id": test_case["id"],
                "category": test_case["category"],
                "status": "error",
                "error": str(error),
                "cwe_passed": False,
                "evidence_passed": False,
                "impact_passed": False
            }

            print(f"  ERROR: {error}")

        results.append(test_result)

    # Calculate evaluation metrics
    successful_runs = [
        result for result in results
        if result["status"] == "success"
    ]

    cwe_passes = sum(
        result["cwe_passed"] for result in successful_runs
    )

    evidence_passes = sum(
        result["evidence_passed"] for result in successful_runs
    )

    impact_passes = sum(
        result["impact_passed"] for result in successful_runs
    )

    successful_count = len(successful_runs)

    metrics = {
        "total_cases": total,
        "successful_runs": successful_count,
        "failed_runs": total - successful_count,
        "cwe_accuracy": (
            cwe_passes / successful_count
            if successful_count else 0
        ),
        "evidence_accuracy": (
            evidence_passes / successful_count
            if successful_count else 0
        ),
        "impact_accuracy": (
            impact_passes / successful_count
            if successful_count else 0
        )
    }

    # Save detailed results
    output = {
        "metrics": metrics,
        "results": results
    }

    with open(OUTPUT_PATH, "w", encoding="utf-8") as file:
        json.dump(output, file, indent=4)

    # Print final report
    print("\n")
    print("=" * 60)
    print("EVALUATION SUMMARY")
    print("=" * 60)

    print(f"Total cases: {metrics['total_cases']}")
    print(f"Successful runs: {metrics['successful_runs']}")
    print(f"Failed runs: {metrics['failed_runs']}")

    print(
        f"CWE accuracy: "
        f"{metrics['cwe_accuracy']:.1%}"
    )

    print(
        f"Evidence accuracy: "
        f"{metrics['evidence_accuracy']:.1%}"
    )

    print(
        f"Impact accuracy: "
        f"{metrics['impact_accuracy']:.1%}"
    )

    print(f"\nDetailed results saved to: {OUTPUT_PATH}")


if __name__ == "__main__":
    run_evaluation()
