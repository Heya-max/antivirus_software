"""
Quarantine Management
Manages quarantined malicious files
"""

import os
import shutil
import datetime
import json


class QuarantineManager:
    def __init__(self, quarantine_dir=None):
        if quarantine_dir is None:
            self.quarantine_dir = os.path.join(os.path.expanduser("~"), ".antivirus_quarantine")
        else:
            self.quarantine_dir = quarantine_dir
        
        self.metadata_file = os.path.join(self.quarantine_dir, "quarantine_metadata.json")
        self.ensure_quarantine_dir()
        self.quarantined_files = self.load_metadata()
    
    def ensure_quarantine_dir(self):
        """Create quarantine directory if it doesn't exist"""
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)
    
    def load_metadata(self):
        """Load quarantine metadata from file"""
        if os.path.exists(self.metadata_file):
            try:
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}
    
    def save_metadata(self):
        """Save quarantine metadata to file"""
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.quarantined_files, f, indent=4)
        except Exception as e:
            print(f"Error saving metadata: {e}")
    
    def quarantine_file(self, filepath, threat_info=None):
        """Move a file to quarantine"""
        if not os.path.exists(filepath):
            return {"success": False, "error": "File not found"}
        
        try:
            # Generate unique ID for the file
            file_id = datetime.datetime.now().strftime("%Y%m%d%H%M%S") + "_" + os.path.basename(filepath)
            quarantine_path = os.path.join(self.quarantine_dir, file_id)
            
            # Copy file to quarantine
            shutil.copy2(filepath, quarantine_path)
            
            # Store metadata
            self.quarantined_files[file_id] = {
                'original_path': filepath,
                'quarantine_path': quarantine_path,
                'original_filename': os.path.basename(filepath),
                'quarantine_date': datetime.datetime.now().isoformat(),
                'threat_info': threat_info or {},
                'size': os.path.getsize(filepath)
            }
            
            self.save_metadata()
            
            # Optionally delete the original file
            # os.remove(filepath)
            
            return {
                "success": True,
                "file_id": file_id,
                "message": f"File quarantined successfully"
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def restore_file(self, file_id):
        """Restore a file from quarantine"""
        if file_id not in self.quarantined_files:
            return {"success": False, "error": "File not found in quarantine"}
        
        try:
            metadata = self.quarantined_files[file_id]
            quarantine_path = metadata['quarantine_path']
            original_path = metadata['original_path']
            
            # Check if original directory exists
            original_dir = os.path.dirname(original_path)
            if not os.path.exists(original_dir):
                original_path = os.path.join(os.path.expanduser("~"), metadata['original_filename'])
            
            # Restore file
            shutil.copy2(quarantine_path, original_path)
            
            # Remove from quarantine
            del self.quarantined_files[file_id]
            os.remove(quarantine_path)
            self.save_metadata()
            
            return {
                "success": True,
                "message": f"File restored to {original_path}"
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def delete_quarantined_file(self, file_id):
        """Permanently delete a quarantined file"""
        if file_id not in self.quarantined_files:
            return {"success": False, "error": "File not found in quarantine"}
        
        try:
            metadata = self.quarantined_files[file_id]
            quarantine_path = metadata['quarantine_path']
            
            if os.path.exists(quarantine_path):
                os.remove(quarantine_path)
            
            del self.quarantined_files[file_id]
            self.save_metadata()
            
            return {
                "success": True,
                "message": "File permanently deleted"
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def list_quarantined_files(self):
        """List all quarantined files"""
        return self.quarantined_files
    
    def get_quarantine_count(self):
        """Get count of quarantined files"""
        return len(self.quarantined_files)
    
    def clear_all_quarantine(self):
        """Clear all quarantined files"""
        try:
            for file_id in list(self.quarantined_files.keys()):
                metadata = self.quarantined_files[file_id]
                quarantine_path = metadata['quarantine_path']
                
                if os.path.exists(quarantine_path):
                    os.remove(quarantine_path)
            
            self.quarantined_files = {}
            self.save_metadata()
            
            return {"success": True, "message": "All quarantine files cleared"}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_file_details(self, file_id):
        """Get details of a quarantined file"""
        if file_id in self.quarantined_files:
            return self.quarantined_files[file_id]
        return None


# Example usage
if __name__ == "__main__":
    qm = QuarantineManager()
    print("Quarantine Manager")
    print("=" * 50)
    print(f"Quarantined files: {qm.get_quarantine_count()}")
