from agent import ICPAgent
from tools.image_tools import create_image_from_prompt
from tools.icp_video_tools import create_video_from_image
from tools.smart_contract_tools import generate_smart_contract
# Define capabilities
capabilities = [
    create_image_from_prompt,
    create_video_from_image,
    generate_smart_contract
]

# Initialize the agent
agent = ICPAgent(capabilities=capabilities, show_planning=True)

# Use the agent
while True:
    user_input = input("Enter your message (or 'quit' to exit): ")
    if user_input.lower() == 'quit':
        break
    
    response = agent(user_input)
    print("Planning:", response.get('planning_text', ''))
    print("Response:", response.get('user_facing_text', ''))