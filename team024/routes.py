"""Flask routes for FIM dashboard"""
import json
from datetime import datetime
from flask import render_template, request, jsonify

from app import db
from models import Event, FileClassification, HashBaseline, AlertConfig, AlertHistory
from config import CLASSIFICATION_LEVELS


def register_routes(app):
    """Register all routes with the Flask app"""
    
    @app.route("/")
    def index():
        """Main dashboard page with advanced filtering"""
        search_query = request.args.get("search", "").strip()
        
        event_types_param = request.args.get("types", "")
        if event_types_param:
            event_types = [t.strip() for t in event_types_param.split(",") if t.strip()]
            if "all" in event_types:
                event_types = None
        else:
            event_types = None
        
        search_columns_param = request.args.get("columns", "")
        if search_columns_param:
            search_columns = [c.strip() for c in search_columns_param.split(",") if c.strip()]
            if "all" in search_columns:
                search_columns = None
        else:
            search_columns = None
        
        query = Event.query
        
        if event_types:
            query = query.filter(Event.event_type.in_(event_types))
        
        if search_query:
            search_term = f"%{search_query}%"
            if search_columns:
                conditions = []
                column_map = {
                    'timestamp': Event.timestamp.cast(db.String).like(search_term),
                    'event_type': Event.event_type.like(search_term),
                    'file_path': Event.file_path.like(search_term),
                    'endpoint': Event.endpoint.like(search_term),
                    'hostname': Event.hostname.like(search_term),
                    'username': Event.username.like(search_term),
                }
                for col in search_columns:
                    if col in column_map:
                        conditions.append(column_map[col])
                if conditions:
                    from sqlalchemy import or_
                    query = query.filter(or_(*conditions))
            else:
                from sqlalchemy import or_
                query = query.filter(or_(
                    Event.file_path.like(search_term),
                    Event.event_type.like(search_term),
                    Event.endpoint.like(search_term),
                    Event.hostname.like(search_term),
                    Event.username.like(search_term)
                ))
        
        events = query.order_by(Event.timestamp.desc()).limit(100).all()
        events_data = [e.to_dict() for e in events]
        
        selected_types = event_types if event_types else ["all"]
        has_active_filters = bool(search_query or (event_types and len(event_types) > 0))
        
        db_connected = True
        
        return render_template(
            "index.html",
            events=events_data,
            search_query=search_query,
            selected_event_types=selected_types,
            selected_search_columns=search_columns if search_columns else ["all"],
            has_active_filters=has_active_filters,
            db_connected=db_connected
        )
    
    @app.route("/classification", methods=["GET"])
    def classification():
        """Classification page for assigning security levels to files"""
        endpoints_param = request.args.get("endpoints", "")
        if endpoints_param:
            selected_endpoints = [e.strip() for e in endpoints_param.split(",") if e.strip()]
        else:
            selected_endpoints = None
        
        search_query = request.args.get("search", "").strip()
        
        subquery = db.session.query(
            Event.file_path,
            db.func.max(Event.timestamp).label('max_timestamp')
        ).group_by(Event.file_path).subquery()
        
        query = db.session.query(Event).join(
            subquery,
            db.and_(
                Event.file_path == subquery.c.file_path,
                Event.timestamp == subquery.c.max_timestamp
            )
        )
        
        if selected_endpoints:
            query = query.filter(Event.endpoint.in_(selected_endpoints))
        
        files_events = query.order_by(Event.timestamp.desc()).all()
        
        files = []
        for event in files_events:
            if search_query and search_query.lower() not in event.file_path.lower():
                continue
            
            classification_record = FileClassification.query.filter_by(
                file_path=event.file_path
            ).first()
            
            files.append({
                'file_path': event.file_path,
                'last_timestamp': event.timestamp.strftime('%Y-%m-%d %H:%M:%S') if event.timestamp else None,
                'endpoint': event.endpoint,
                'hostname': event.hostname,
                'username': event.username,
                'classification': classification_record.classification if classification_record else None,
                'classification_id': classification_record.id if classification_record else None
            })
        
        available_endpoints = db.session.query(Event.endpoint).distinct().all()
        available_endpoints = [e[0] for e in available_endpoints if e[0]]
        
        return render_template(
            "classification.html",
            files=files,
            available_endpoints=available_endpoints,
            selected_endpoints=selected_endpoints if selected_endpoints else [],
            search_query=search_query,
            db_connected=True
        )
    
    @app.route("/classification/save-all", methods=["POST"])
    def classification_save_all():
        """AJAX endpoint to save all classifications at once"""
        files_json = request.form.get("files")
        if not files_json:
            return jsonify({"success": False, "message": "Missing files parameter"}), 400
        
        try:
            files = json.loads(files_json)
        except json.JSONDecodeError:
            return jsonify({"success": False, "message": "Invalid JSON format"}), 400
        
        if not isinstance(files, list):
            return jsonify({"success": False, "message": "Files must be a list"}), 400
        
        saved_count = 0
        for file_data in files:
            file_path = file_data.get("file_path")
            classification = file_data.get("classification", "").strip()
            endpoint = file_data.get("endpoint")
            hostname = file_data.get("hostname")
            username = file_data.get("username")
            
            if not file_path:
                continue
            
            existing = FileClassification.query.filter_by(file_path=file_path).first()
            
            if not classification:
                if existing:
                    db.session.delete(existing)
            else:
                if existing:
                    existing.classification = classification
                    existing.last_updated_timestamp = datetime.utcnow()
                    existing.endpoint = endpoint
                    existing.hostname = hostname
                    existing.username = username
                else:
                    new_classification = FileClassification(
                        file_path=file_path,
                        classification=classification,
                        endpoint=endpoint,
                        hostname=hostname,
                        username=username
                    )
                    db.session.add(new_classification)
            
            saved_count += 1
        
        try:
            db.session.commit()
            return jsonify({
                "success": True,
                "message": f"Successfully saved {saved_count} classification(s)"
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": str(e)}), 500
    
    @app.route("/classification/update", methods=["POST"])
    def classification_update():
        """AJAX endpoint to update classification without page reload"""
        file_path = request.form.get("file_path")
        classification = request.form.get("classification", "").strip()
        endpoint = request.form.get("endpoint")
        hostname = request.form.get("hostname")
        username = request.form.get("username")
        
        if not file_path:
            return jsonify({"success": False, "message": "Missing file_path parameter"}), 400
        
        existing = FileClassification.query.filter_by(file_path=file_path).first()
        
        if not classification:
            if existing:
                db.session.delete(existing)
                db.session.commit()
            return jsonify({"success": True, "message": "Classification cleared successfully"})
        
        if existing:
            existing.classification = classification
            existing.last_updated_timestamp = datetime.utcnow()
            existing.endpoint = endpoint
            existing.hostname = hostname
            existing.username = username
        else:
            new_classification = FileClassification(
                file_path=file_path,
                classification=classification,
                endpoint=endpoint,
                hostname=hostname,
                username=username
            )
            db.session.add(new_classification)
        
        try:
            db.session.commit()
            return jsonify({"success": True, "message": "Classification updated successfully"})
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": str(e)}), 500
    
    @app.route("/alerts", methods=["GET"])
    def alerts_page():
        """Alert configuration page"""
        configs = AlertConfig.query.all()
        return render_template("alerts.html", configs=configs, db_connected=True)
    
    @app.route("/alerts/config", methods=["POST"])
    def alerts_config_save():
        """Save or update alert configuration"""
        config_id = request.form.get("config_id")
        name = request.form.get("name", "").strip()
        webhook_url = request.form.get("webhook_url", "").strip()
        is_active = request.form.get("is_active") == "on"
        alert_on_created = request.form.get("alert_on_created") == "on"
        alert_on_modified = request.form.get("alert_on_modified") == "on"
        alert_on_deleted = request.form.get("alert_on_deleted") == "on"
        min_classification = request.form.get("min_classification", "Unclassified")
        
        if not name or not webhook_url:
            return jsonify({"success": False, "message": "Name and webhook URL are required"}), 400
        
        if config_id:
            config = AlertConfig.query.get(int(config_id))
            if config:
                config.name = name
                config.webhook_url = webhook_url
                config.is_active = is_active
                config.alert_on_created = alert_on_created
                config.alert_on_modified = alert_on_modified
                config.alert_on_deleted = alert_on_deleted
                config.min_classification = min_classification
        else:
            config = AlertConfig(
                name=name,
                webhook_url=webhook_url,
                is_active=is_active,
                alert_on_created=alert_on_created,
                alert_on_modified=alert_on_modified,
                alert_on_deleted=alert_on_deleted,
                min_classification=min_classification
            )
            db.session.add(config)
        
        try:
            db.session.commit()
            return jsonify({"success": True, "message": "Alert configuration saved"})
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": str(e)}), 500
    
    @app.route("/alerts/config/<int:config_id>", methods=["DELETE"])
    def alerts_config_delete(config_id):
        """Delete an alert configuration"""
        config = AlertConfig.query.get(config_id)
        if config:
            db.session.delete(config)
            db.session.commit()
            return jsonify({"success": True, "message": "Configuration deleted"})
        return jsonify({"success": False, "message": "Configuration not found"}), 404
    
    @app.route("/api/status")
    def api_status():
        """API endpoint to check system status"""
        return jsonify({
            "status": "running",
            "db_connected": True,
            "watcher_active": True
        })
    
    @app.route("/api/events")
    def api_events():
        """API endpoint to get recent events"""
        limit = request.args.get("limit", 100, type=int)
        event_type = request.args.get("type")
        
        query = Event.query
        if event_type and event_type != "all":
            query = query.filter_by(event_type=event_type)
        
        events = query.order_by(Event.timestamp.desc()).limit(limit).all()
        return jsonify([e.to_dict() for e in events])
    
    @app.route("/api/baselines")
    def api_baselines():
        """API endpoint to get hash baselines"""
        baselines = HashBaseline.query.all()
        return jsonify([b.to_dict() for b in baselines])
    
    @app.route("/api/webhook/test", methods=["POST"])
    def webhook_test():
        """Test webhook endpoint for n8n integration"""
        data = request.get_json() or {}
        return jsonify({
            "success": True,
            "message": "Webhook received",
            "data": data
        })
